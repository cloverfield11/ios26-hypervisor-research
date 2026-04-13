# Apple Ships a Full Hypervisor on Your iPhone — And It's Already Turned On

### Static RE of SPTM Virtualization Infrastructure in iOS 26

**Author:** Igor Gaponenko  
**Date:** April 13, 2026  
**Target:** iOS 26.4.1 (23E254), iPhone 14 Pro (A16 Bionic, t8120)  
**XNU Source:** xnu-12377.1.9 (Darwin 25, open-source release)  
**Tools:** [blacktop/ipsw](https://github.com/blacktop/ipsw) v3.1.671, Python, ARM64 manual decoding

---

## TL;DR

**Apple ships a complete, enabled hypervisor on every iPhone with A15+ silicon running iOS 26.** Through static analysis of the SPTM firmware, XNU kernelcache, and device tree extracted from a signed IPSW, we prove:

1. The SPTM firmware contains a full VM API: guest enter/exit, Stage-2 page tables, VMID allocation, and ARMv8.4-NV2 nested virtualization support
2. The XNU kernelcache contains embedded Hypervisor framework code (`hv_vcpu.c`, `hv_vm_t`, `hv_nested_vm_t`)
3. The gate is a device tree property `/product/has-virtualization`
4. **This property is set to `1` in the production device tree shipped with iOS 26.4.1 for iPhone 14 Pro**
5. The only remaining barrier is the `com.apple.private.hypervisor` entitlement

This is, to our knowledge, the **first public documentation** that Apple enables the hardware hypervisor on consumer iPhones.

---

## Table of Contents

- [Background: What is SPTM?](#background-what-is-sptm)
- [Methodology](#methodology)
- [Phase 1: XNU Source Analysis](#phase-1-xnu-source-analysis)
- [Phase 2: SPTM Binary Strings](#phase-2-sptm-binary-strings)
- [Phase 3: Kernelcache Analysis](#phase-3-kernelcache-analysis)
- [Phase 4: The Gate — Decompilation](#phase-4-the-gate--decompilation)
- [Phase 5: Device Tree — The Proof](#phase-5-device-tree--the-proof)
- [Architecture](#architecture)
- [Implications](#implications)
- [Appendix: Complete Data Tables](#appendix-complete-data-tables)

---

## Background: What is SPTM?

Starting with iOS 17 on A15+ silicon, Apple replaced the Page Protection Layer (PPL) with a new security architecture called **SPTM** (Secure Page Table Monitor). SPTM runs at **GL2** — a privilege level provided by Apple's proprietary **Guarded Execution Facility (GXF)** extension, which is orthogonal to ARM's standard EL0–EL3 hierarchy.

```
┌─────────────────────────────────────────┐
│           Apple Silicon SoC             │
├─────────┬─────────┬─────────┬───────────┤
│  EL0    │  EL1    │  GL1    │   GL2     │
│  User   │  XNU    │  SK     │   SPTM    │
│  Apps   │ Kernel  │ Secure  │  Page     │
│         │         │ Kernel  │  Table    │
│         │         │         │  Monitor  │
└─────────┴─────────┴─────────┴───────────┘
```

SPTM owns all page table modifications, memory retyping, and — as we now demonstrate — **virtual machine management**. XNU communicates with SPTM via the `GENTER` instruction, which transitions execution from EL1 to GL2 through a dispatch table.

Key prior work:
- [arXiv 2510.09272](https://arxiv.org/abs/2510.09272) — SPTM architecture overview
- [Dataflow Forensics](https://www.df-f.com/blog/sptm4) — "SPTM: The Last Bits" (Nov 2025)
- [Jonathan Levin](https://newosxbook.com/bonus/sptm2.html) — SPTM Part 2

---

## Methodology

All analysis was performed **entirely offline** using files extracted from a publicly available, Apple-signed IPSW. No jailbreak, no on-device access, no proprietary tools.

### Extraction Pipeline

```bash
# 1. Install ipsw tool
curl -sL -o ipsw.tar.gz \
  "https://github.com/blacktop/ipsw/releases/download/v3.1.671/ipsw_3.1.671_macOS_x86_64.tar.gz"
tar xzf ipsw.tar.gz

# 2. Remote-extract kernelcache (no full IPSW download needed)
./ipsw download ipsw --device iPhone15,2 --latest --kernel -y

# 3. Remote-extract SPTM firmware
./ipsw download ipsw --device iPhone15,2 --latest --pattern 'sptm' -y

# 4. Remote-extract DeviceTree
./ipsw download ipsw --device iPhone15,2 --latest --pattern 'DeviceTree' -y

# 5. Decode IM4P containers to raw binaries
./ipsw img4 im4p extract Firmware/sptm.t8120.release.im4p -o sptm.t8120.bin
./ipsw img4 im4p extract Firmware/all_flash/DeviceTree.d73ap.im4p -o DeviceTree.bin
```

### Artifacts Analyzed

| File | Size | Description |
|---|---|---|
| `sptm.t8120.bin` | 1.1 MB | SPTM firmware, MachO ARM64e |
| `kernelcache.release.iPhone15,2` | 59 MB | Fileset MachO, ARM64e |
| `kernelcache.research.iPhone15,2` | 59 MB | Research variant |
| `DeviceTree.d73ap.im4p` | 49 KB | Apple Device Tree |
| XNU xnu-12377.1.9 source | — | [apple-oss-distributions/xnu](https://github.com/apple-oss-distributions/xnu) |

---

## Phase 1: XNU Source Analysis

Apple open-sources XNU, but **systematically redacts** Stage-2 virtualization code paths. The redaction is consistent and deliberate:

### The Redaction Pattern

Every function that handles VM/Stage-2 paths has the same construct:

```c
// osfmk/arm64/sptm/pmap/pmap.c — xnu-12377.1.9
static sptm_frame_type_t get_sptm_pt_type(pmap_t pmap) {
    const bool is_stage2_pmap = false;  // ← HARDCODED
    if (is_stage2_pmap) {
        return XNU_STAGE2_PAGE_TABLE;   // ← Dead code in source
    } else {
        return pmap->type == PMAP_TYPE_NESTED ? XNU_PAGE_TABLE_SHARED : XNU_PAGE_TABLE;
    }
}
```

This pattern repeats across `pmap_create_options_internal()`, `pmap_tt1_allocate()`, `pmap_tt1_deallocate()`, `pmap_destroy_internal()`, and others. Each has `const bool is_stage2 = false` or `const bool is_stage2_pmap = false`.

The public API function is similarly neutered:

```c
bool pmap_performs_stage2_translations(__unused pmap_t pmap) {
    return false;  // ← Always false in open source
}
```

### What the Source DOES Reveal

Despite the redaction, the infrastructure is fully visible:

**1. `PMAP_CREATE_STAGE2` is a valid flag** (from `osfmk/vm/pmap.h`):
```c
#define PMAP_CREATE_KNOWN_FLAGS (PMAP_CREATE_64BIT | PMAP_CREATE_STAGE2 | \
    PMAP_CREATE_DISABLE_JOP | PMAP_CREATE_FORCE_4K_PAGES | ...)
```

**2. The pmap struct has a VMID field:**
```c
// osfmk/arm64/sptm/pmap/pmap.h
union {
    uint16_t asid;   // Process address space ID
    uint16_t vmid;   // Virtual Machine ID
};
```

**3. VMID architecture:** 256 hardware VMIDs, even=SK, odd=XNU → 128 usable.

**4. Stage-2 page table geometry exists:**
```c
pmap_table_level_info_4k_stage2[]  // Full 4K Stage-2 with 40-bit IPA
```

**5. SPTM accepts VM frame types:**
```c
sptm_retype(pa, XNU_DEFAULT, XNU_STAGE2_ROOT_TABLE, retype_params);
// retype_params.vmid = pmap->vmid  (for Stage-2)
// retype_params.asid = pmap->asid  (for Stage-1)
```

---

## Phase 2: SPTM Binary Strings

String analysis of the **production** SPTM firmware reveals the complete VM subsystem. These strings are in the shipping A16 binary — not debug, not development.

### VM API Functions

```
sptm_guest_enter
sptm_guest_exit
sptm_guest_dispatch
sptm_guest_va_to_ipa
sptm_guest_stage1_tlb_op
```

### VM State Machine

```
STATE_XNU_GUEST
EVENT_ENTER_GUEST
EVENT_EXIT_GUEST
```

### Stage-2 Infrastructure

```
acquire_stage2_root_pt
stage2_root_pt
stage2_root_pt_fte->type
stage2_root_pt_tsd->vmid
XNU_STAGE2_PAGE_TABLE
XNU_STAGE2_ROOT_TABLE
current_vmid
validate_vmid
```

### VMID Bitmap (present, not stripped!)

```
%s: VMID 0x%hx was already clear in sptm_vmid_bitmap
```

### NV2 Nested Virtualization

```
VIOLATION_GUEST_ILLEGAL_NV2_BADDR
```

This proves Apple silicon implements **ARMv8.4-NV2** (Nested Virtualization v2 with VNCR page). The SPTM validates NV2 base addresses, meaning the hardware supports running a hypervisor inside a VM.

### The Boot Gate

```
bootstrap_determine_virtualization_support
has-virtualization
device_is_prod_fused_init
```

### Violation Strings (error paths — prove functional code)

| String | Meaning |
|---|---|
| `VIOLATION_GUEST_ENTER_INTERRUPTS_ENABLED` | Can't enter guest with interrupts on |
| `VIOLATION_GUEST_ILLEGAL_NV2_BADDR` | Invalid NV2 base address |
| `VIOLATION_GUEST_INVALID_S1_TLB_OP` | Invalid guest TLB operation |
| `VIOLATION_ILLEGAL_VIRTUALIZATION_CALL` | VM call not permitted |
| `VIOLATION_INVALID_VMID` | Bad VMID |
| `VIOLATION_VMID_IN_USE` | VMID collision |

---

## Phase 3: Kernelcache Analysis

The XNU kernelcache contains **embedded Hypervisor framework code** — there is no separate `AppleHypervisor` kext. The code is compiled directly into `com.apple.kernel`.

### Kernel Objects

| String | Type |
|---|---|
| `hv_vm_t` | VM kernel object |
| `hv_nested_vm_t` | Nested VM object |
| `hv_mem_notify_t` | Memory notification object |
| `IKOT_HYPERVISOR` | Mach port type |

### Source Files Compiled In

```
hv_vcpu.c          ← vCPU implementation
```

### Entitlements

```
com.apple.private.hypervisor
com.apple.private.hypervisor.vmapple
com.apple.security.hypervisor
```

### Sysctl Interface

```
kern.hv_vmm_present     ← Is VMM available?
kern.hv_support          ← HV support status
kern.hv_disable          ← HV disable switch
```

### Boot Initialization

`hv_support_init` runs between `kdp_init` and `PE_init_iokit` during kernel boot.

### Release vs Research: Identical

Diff between release and research kernelcache HV strings: **empty**. Both contain identical hypervisor infrastructure.

---

## Phase 4: The Gate — Decompilation

We located the single xref to the `"has-virtualization"` string in SPTM code at `0xfffffff0270d36b8` and manually decompiled the surrounding function using `ipsw macho disass` and a custom Python ADRP/ADD xref scanner.

### Decompiled `bootstrap_determine_virtualization_support()`

```c
// Inline in sptm_bootstrap_late()
// No separate function — embedded in the main bootstrap routine

void virtualization_gate(dt_root) {
    dt_node_t *product_node = NULL;
    dt_prop_t *prop = NULL;
    uint32_t prop_size;
    
    // Step 1: Find "/product" node in device tree
    if (dt_find_node(dt_root, 0, "/product", &product_node) != 1)
        return;  // Node not found → virt disabled
    
    // Step 2: Read "has-virtualization" property
    if (dt_get_property(product_node, "has-virtualization",
                        &prop, &prop_size) != 1)
        return;  // Property not found → virt disabled
    
    // Step 3: Store result
    uint32_t value = *(uint32_t *)prop;
    g_virtualization_supported = (value != 0);  // → 0xfffffff02708dc40
}
```

### Annotated Assembly

```asm
; Find "/product" device tree node
0xfffffff0270d3688:  ldr  x0, [x22, #0xa70]     ; DT root
0xfffffff0270d368c:  adrp x2, <page>
0xfffffff0270d3690:  add  x2, x2, #0x60e         ; "/product"
0xfffffff0270d3698:  mov  x1, #0
0xfffffff0270d369c:  bl   dt_find_node
0xfffffff0270d36a0:  cmp  w0, #1
0xfffffff0270d36a4:  b.ne skip                    ; not found → skip

; Get "has-virtualization" property
0xfffffff0270d36b8:  adrp x1, <page>
0xfffffff0270d36bc:  add  x1, x1, #0x660          ; "has-virtualization"
0xfffffff0270d36c8:  bl   dt_get_property
0xfffffff0270d36cc:  cmp  w0, #1
0xfffffff0270d36d0:  b.ne done                    ; not found → leave as 0

; Read value, convert to bool, store
0xfffffff0270d36d4:  ldur x8, [fp, #-0x60]        ; prop pointer
0xfffffff0270d36d8:  ldr  w8, [x8]                ; value (uint32)
0xfffffff0270d36dc:  cmp  w8, #0
0xfffffff0270d36e0:  cset w8, ne                   ; bool: 1 if nonzero
0xfffffff0270d36e4:  adrp x9, <page>
0xfffffff0270d36e8:  strb w8, [x9, #0xc40]        ; STORE → 0xfffffff02708dc40
```

### Key Properties of the Gate

| Property | Value |
|---|---|
| **DT node path** | `/product` |
| **DT property name** | `has-virtualization` |
| **Fuse check** | **NO** — `device_is_prod_fused_init` is in a separate code block |
| **Boot-arg override** | **NO** — no `PE_parse_boot_argn` in this path |
| **Result storage** | `0xfffffff02708dc40` — 1 byte in `__LATE_CONST` |
| **Read-once** | Yes — set during boot, never re-evaluated |

### All Consumers of `g_virtualization_supported`

| Address | Operation | Context |
|---|---|---|
| `0xfffffff0270d36e4` | **STRB** | Bootstrap — sets the flag |
| `0xfffffff0270d7f74` | LDRB → TBZ | Dispatch table validator |
| `0xfffffff0270dcc40` | LDRB → TBNZ | `genter_dispatch_entry` (`dispatch.c:1410`) |
| `0xfffffff0270e62e8` | LDRB → TBZ | Retype handler |

All three consumers follow the same pattern:
```asm
ldrb w9, [x9, #0xc40]     ; load virtualization_supported
tbz  w9, #0, <violation>   ; if 0 → deny/panic
```

---

## Phase 5: Device Tree — The Proof

We extracted the DeviceTree from the same signed IPSW (`DeviceTree.d73ap.im4p` for iPhone 14 Pro) and searched for the property.

### Raw Hex Dump

```
Offset    Hex                                       ASCII
────────────────────────────────────────────────────────────
0x3862c:  68 61 73 2d 76 69 72 74 75 61 6c 69 7a   has-virtualiz
0x38639:  61 74 69 6f 6e 00 00 00 00 00 00 00 00   ation........
0x38646:  00 00 00 00 00 00 00 00 00 00             ..........
0x3864c:  04 00 00 00                               size = 4
0x38650:  01 00 00 00                               VALUE = 1 ✅
```

### Result

```
/product/has-virtualization = 1  (uint32_t, little-endian)
```

**Virtualization is enabled on the production iPhone 14 Pro.**

### Additional VM Device Tree Properties

| Property | Offset | Value |
|---|---|---|
| `has-virtualization` | `0x3862c` | `1` (uint32) |
| `vm-reserve` | `0x1a960` | base=`0x10000004000`, size=`0x1000000c000` (~1TB IPA) |
| `allow-vm-reserve-mapping` | `0x1aa8c` | present (empty flag) |

The `vm-reserve` property allocates a ~1 TB virtual address range for Stage-2 IPA (Intermediate Physical Address) space. This is the address space visible to guest VMs.

---

## Architecture

The complete virtualization stack, as reconstructed from this analysis:

```
┌────────────────────────────────────────────────────────────────┐
│                        User Space                              │
│  ┌──────────────┐                                              │
│  │  Application │──── com.apple.private.hypervisor ───────┐    │
│  └──────────────┘                                         │    │
│                     Hypervisor.framework                   │    │
│                        hv_vm_create()                      │    │
│                        hv_vcpu_run()                       │    │
├────────────────────────────────────────────────────────────┤    │
│                     XNU Kernel (EL1)                       │    │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────┐  │    │
│  │ hv_support_init │  │  hv_vcpu.c   │  │  pmap.c      │  │    │
│  │ kern.hv_vmm_    │  │  hv_vm_t     │  │  PMAP_CREATE │  │    │
│  │   present = ?   │  │  hv_nested_  │  │  _STAGE2     │  │    │
│  │ kern.hv_disable │  │    vm_t      │  │  pmap->vmid  │  │    │
│  └─────────────────┘  └──────┬───────┘  └──────┬───────┘  │    │
│                              │ GENTER          │ GENTER    │    │
├──────────────────────────────┼─────────────────┼───────────┤    │
│                     SPTM (GL2)                             │    │
│  ┌────────────────────────────────────────────────────────┐ │    │
│  │  bootstrap_determine_virtualization_support()          │ │    │
│  │  → reads /product/has-virtualization from DT           │ │    │
│  │  → stores to g_virtualization_supported (0x...dc40)    │ │    │
│  ├────────────────────────────────────────────────────────┤ │    │
│  │              VM Dispatch (when flag = 1)               │ │    │
│  │  ┌──────────────────┐  ┌────────────────────────────┐ │ │    │
│  │  │ sptm_guest_enter │  │ sptm_guest_va_to_ipa       │ │ │    │
│  │  │ sptm_guest_exit  │  │ sptm_guest_stage1_tlb_op   │ │ │    │
│  │  │ sptm_guest_      │  │ acquire_stage2_root_pt     │ │ │    │
│  │  │   dispatch       │  │ sptm_vmid_bitmap           │ │ │    │
│  │  └──────────────────┘  └────────────────────────────┘ │ │    │
│  ├────────────────────────────────────────────────────────┤ │    │
│  │              State Machine                            │ │    │
│  │  STATE_XNU_GUEST ←→ EVENT_ENTER/EXIT_GUEST            │ │    │
│  └────────────────────────────────────────────────────────┘ │    │
├────────────────────────────────────────────────────────────┤    │
│                     Hardware                               │    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │    │
│  │  VTTBR_EL2   │  │  Stage-2     │  │  NV2 (Nested     │ │    │
│  │  (per-VM)    │  │  Page Tables │  │   Virtualization) │ │    │
│  └──────────────┘  └──────────────┘  └──────────────────┘ │    │
└────────────────────────────────────────────────────────────────┘
```

---

## Implications

### 1. The Hypervisor is Production-Ready

This is not prototype code. The string analysis shows:
- **Error handling**: 6 `VIOLATION_GUEST_*` error types with specific messages
- **Input sanitization**: `sanitize_integer()` on guest state and Stage-2 root table addresses
- **State machine**: Full enter/exit lifecycle
- **VMID management**: Bitmap allocator with collision detection
- **Nested virtualization**: NV2 BADDR validation

### 2. Possible Use Cases

Why would Apple enable a hypervisor on consumer iPhones?

- **Exclaves**: iOS 26 introduces "exclaves" — isolated execution domains. These may use VM isolation under the hood.
- **Secure containers**: Privacy-sensitive operations could run in hardware-isolated VMs.
- **Future developer features**: Apple may be preparing to ship Hypervisor.framework for iOS, enabling VM-based development tools.
- **Code signing enforcement**: VMs provide an additional layer for dynamic code analysis sandboxing.

### 3. The Entitlement Barrier

The practical barrier is `com.apple.private.hypervisor` — a **restricted entitlement** that Apple does not grant to third-party apps. However:

- On **jailbroken devices**: AMFI bypass removes entitlement checks
- On **SRD** (Security Research Devices): Extended entitlements may be available
- On **macOS**: This entitlement IS available to developers (Virtualization.framework)
- A future iOS SDK update could expose it publicly

---

## Appendix: Complete Data Tables

### A. XNU Frame Types (from pmap.c usage)

```
XNU_DEFAULT                  XNU_COMMPAGE_RO
XNU_COMMPAGE_RW              XNU_COMMPAGE_RX
XNU_KERNEL_RESTRICTED        XNU_PAGE_TABLE
XNU_PAGE_TABLE_COMMPAGE      XNU_PAGE_TABLE_ROZONE
XNU_PAGE_TABLE_SHARED        XNU_PROTECTED_IO
XNU_ROZONE                   XNU_SHARED_ROOT_TABLE
XNU_STAGE2_PAGE_TABLE  ←     XNU_STAGE2_ROOT_TABLE  ←
XNU_SUBPAGE_USER_ROOT_TABLES XNU_USER_DEBUG
XNU_USER_EXEC                XNU_USER_JIT
XNU_USER_ROOT_TABLE
```

### B. SPTM API Functions (XNU-side, from pmap.c)

```
sptm_retype              sptm_map_page           sptm_map_table
sptm_unmap_region        sptm_unmap_table        sptm_update_region
sptm_configure_root      sptm_switch_root        sptm_nest_region
sptm_unnest_region       sptm_surt_alloc         sptm_surt_free
sptm_features_available  sptm_sign_user_pointer  sptm_auth_user_pointer
sptm_update_disjoint     sptm_unmap_disjoint     sptm_kvtophys
sptm_iofilter_protected_write                    ...
```

### C. PMAP_CREATE Flags (from source)

```
PMAP_CREATE_64BIT
PMAP_CREATE_STAGE2         ← Bit value redacted (likely 0x02)
PMAP_CREATE_DISABLE_JOP
PMAP_CREATE_FORCE_4K_PAGES
PMAP_CREATE_ROSETTA
PMAP_CREATE_TEST
PMAP_CREATE_NESTED  = 0x80
```

### D. SPTM Binary Layout

```
Segment         VA Range                          Size    Contents
__TEXT          0xfffffff027004000–027018000       80 KB   Strings, constants
__DATA_CONST    0xfffffff027018000–027020000       32 KB   Read-only data
__LATE_CONST    0xfffffff027020000–027094000      464 KB   Mutable-once data
__TEXT_EXEC     0xfffffff027094000–0270f0000      368 KB   Code
__DATA          0xfffffff0270f4000–027104000       64 KB   BSS, globals
__BOOTDATA      0xfffffff027104000–027118000       80 KB   Boot-time data

g_virtualization_supported: 0xfffffff02708dc40 (__LATE_CONST)
```

### E. Verification Commands

```bash
# Reproduce this analysis:
./ipsw download ipsw --device iPhone15,2 --latest --kernel -y
./ipsw download ipsw --device iPhone15,2 --latest --pattern 'sptm' -y
./ipsw download ipsw --device iPhone15,2 --latest --pattern 'DeviceTree' -y
./ipsw img4 im4p extract Firmware/sptm.t8120.release.im4p -o sptm.bin
./ipsw img4 im4p extract Firmware/all_flash/DeviceTree.d73ap.im4p -o dt.bin

# Check SPTM VM strings:
strings sptm.bin | grep -E 'guest|stage2|vmid|virtualization'

# Check DeviceTree:
strings dt.bin | grep 'has-virtualization'

# Check value (offset may vary per build):
python3 -c "
d=open('dt.bin','rb').read()
i=d.find(b'has-virtualization')
import struct
v=struct.unpack('<I',d[i+36:i+40])[0]
print(f'has-virtualization = {v}')
"
```

---

## Acknowledgments

- **blacktop** for the incredible [ipsw](https://github.com/blacktop/ipsw) tool
- **Dataflow Forensics** for their SPTM research series
- **Jonathan Levin** for *OS Internals and SPTM documentation
- The researchers behind arXiv 2510.09272

---

*This research was conducted entirely through static analysis of publicly available, Apple-signed firmware. No devices were compromised, no vulnerabilities were exploited, and no security mechanisms were bypassed.*
