// =============================================================
// Syscall-Factory (Rust port) — ztsec agent
// Original C header: kas-sec, MIT License, 2025
// version 1.0.0
// =============================================================
//
// Windows x86-64 only for runtime paths; crypto and SafePtr compile on all
// platforms so the test suite can run in CI on Linux runners too.
//
// Include from other modules:
//   mod syscalls; — or — use crate::syscalls::*;
//
// Example:
//   let status = syscall!("NtAllocateVirtualMemory",
//                         proc, &mut base, 0usize, &mut size, MEM_COMMIT, PAGE_READWRITE);

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use core::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// crypto — compile-time and runtime hashing (platform-agnostic)
// ---------------------------------------------------------------------------

pub mod crypto {
    pub const RANDOM_SEED: u32 = 0x811C9DC5;
    pub const ENV_KEY: u32 = 0;

    pub const SEED: u32 = RANDOM_SEED ^ ENV_KEY;
    pub const OBF_OFFSET: u32 = 0x811C9DC5u32 ^ SEED;
    pub const OBF_PRIME: u32 = 0x01000193u32 ^ SEED;
    pub const PTR_KEY: u64 = (SEED as u64) | ((SEED as u64) << 32);

    #[inline(always)]
    pub const fn rotr32(value: u32, shift: u32) -> u32 {
        value.rotate_right(shift)
    }

    /// Compile-time FNV-variant hash over a byte slice (no null needed).
    pub const fn hash_str(s: &[u8]) -> u32 {
        let mut h: u32 = OBF_OFFSET ^ SEED;
        let p: u32 = OBF_PRIME ^ SEED;
        let mut i = 0usize;
        while i < s.len() {
            h ^= s[i] as u32;
            h = h.wrapping_mul(p);
            h = rotr32(h, 13);
            i += 1;
        }
        h
    }

    /// Runtime C-string hash (stops at null byte).
    ///
    /// # Safety
    ///
    /// `ptr` must be valid for reads through a terminating NUL byte.
    pub unsafe fn hash_cstr(ptr: *const u8) -> u32 {
        let mut h: u32 = OBF_OFFSET ^ SEED;
        let p: u32 = OBF_PRIME ^ SEED;
        let mut i = 0isize;
        loop {
            let b = unsafe { *ptr.offset(i) };
            if b == 0 {
                break;
            }
            h ^= b as u32;
            h = h.wrapping_mul(p);
            h = rotr32(h, 13);
            i += 1;
        }
        h
    }

    /// Runtime hash over a UTF-16LE wide buffer, ASCII-lowercased.
    /// `byte_len` is in bytes (i.e. char count × 2), matching UNICODE_STRING.Length.
    ///
    /// # Safety
    ///
    /// `buf` must be non-null, properly aligned for `u16`, and valid for reads of
    /// `(byte_len / 2)` `u16` values.
    pub unsafe fn hash_wide(buf: *const u16, byte_len: u16) -> u32 {
        let mut h: u32 = OBF_OFFSET ^ SEED;
        let p: u32 = OBF_PRIME ^ SEED;
        let char_count = (byte_len / 2) as usize;
        for i in 0..char_count {
            let mut c = unsafe { *buf.add(i) };
            if c >= b'A' as u16 && c <= b'Z' as u16 {
                c += 32;
            }
            h ^= (c & 0xFF) as u32;
            h = h.wrapping_mul(p);
            h = rotr32(h, 13);
        }
        h
    }
}

/// Compile-time string hash macro.
#[macro_export]
macro_rules! hash {
    ($s:expr) => {
        crate::syscalls::crypto::hash_str($s.as_bytes())
    };
}

// ---------------------------------------------------------------------------
// SafePtr — XOR-encoded atomic pointer (platform-agnostic)
// ---------------------------------------------------------------------------

pub struct SafePtr {
    enc: AtomicUsize,
}

impl SafePtr {
    pub const fn new() -> Self {
        Self { enc: AtomicUsize::new(0) }
    }

    pub fn get(&self) -> *mut u8 {
        let val = self.enc.load(Ordering::Acquire);
        if val == 0 {
            return core::ptr::null_mut();
        }
        (val ^ crypto::PTR_KEY as usize) as *mut u8
    }

    /// CAS: write only if currently null. Returns true on success.
    pub fn set_if_null(&self, new_val: *mut u8) -> bool {
        let enc_val = (new_val as usize) ^ (crypto::PTR_KEY as usize);
        self.enc
            .compare_exchange(0, enc_val, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

impl Default for SafePtr {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl Sync for SafePtr {}
unsafe impl Send for SafePtr {}

// ---------------------------------------------------------------------------
// Everything below is Windows x86-64 only.
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows_impl {
    use super::*;

    // -----------------------------------------------------------------------
    // Minimal PE / PEB structs
    // -----------------------------------------------------------------------

    #[repr(C)]
    pub struct ListEntry {
        pub flink: *mut ListEntry,
        pub blink: *mut ListEntry,
    }

    #[repr(C)]
    pub struct UnicodeString {
        pub length: u16,
        pub maximum_length: u16,
        pub buffer: *const u16,
    }

    #[repr(C)]
    pub struct ImageDosHeader {
        pub e_magic: u16,
        pub e_cblp: u16,
        pub e_cp: u16,
        pub e_crlc: u16,
        pub e_cparhdr: u16,
        pub e_minalloc: u16,
        pub e_maxalloc: u16,
        pub e_ss: u16,
        pub e_sp: u16,
        pub e_csum: u16,
        pub e_ip: u16,
        pub e_cs: u16,
        pub e_lfarlc: u16,
        pub e_ovno: u16,
        pub e_res: [u16; 4],
        pub e_oemid: u16,
        pub e_oeminfo: u16,
        pub e_res2: [u16; 10],
        pub e_lfanew: i32,
    }

    #[repr(C)]
    pub struct ImageFileHeader {
        pub machine: u16,
        pub number_of_sections: u16,
        pub time_date_stamp: u32,
        pub pointer_to_symbol_table: u32,
        pub number_of_symbols: u32,
        pub size_of_optional_header: u16,
        pub characteristics: u16,
    }

    #[repr(C)]
    pub struct ImageDataDirectory {
        pub virtual_address: u32,
        pub size: u32,
    }

    #[repr(C)]
    pub struct ImageOptionalHeader64 {
        pub magic: u16,
        pub major_linker_version: u8,
        pub minor_linker_version: u8,
        pub size_of_code: u32,
        pub size_of_initialized_data: u32,
        pub size_of_uninitialized_data: u32,
        pub address_of_entry_point: u32,
        pub base_of_code: u32,
        pub image_base: u64,
        pub section_alignment: u32,
        pub file_alignment: u32,
        pub major_os_version: u16,
        pub minor_os_version: u16,
        pub major_image_version: u16,
        pub minor_image_version: u16,
        pub major_subsystem_version: u16,
        pub minor_subsystem_version: u16,
        pub win32_version_value: u32,
        pub size_of_image: u32,
        pub size_of_headers: u32,
        pub check_sum: u32,
        pub subsystem: u16,
        pub dll_characteristics: u16,
        pub size_of_stack_reserve: u64,
        pub size_of_stack_commit: u64,
        pub size_of_heap_reserve: u64,
        pub size_of_heap_commit: u64,
        pub loader_flags: u32,
        pub number_of_rva_and_sizes: u32,
        pub data_directory: [ImageDataDirectory; 16],
    }

    #[repr(C)]
    pub struct ImageNtHeaders64 {
        pub signature: u32,
        pub file_header: ImageFileHeader,
        pub optional_header: ImageOptionalHeader64,
    }

    #[repr(C)]
    pub struct ImageSectionHeader {
        pub name: [u8; 8],
        pub virtual_size: u32,
        pub virtual_address: u32,
        pub size_of_raw_data: u32,
        pub pointer_to_raw_data: u32,
        pub pointer_to_relocations: u32,
        pub pointer_to_line_numbers: u32,
        pub number_of_relocations: u16,
        pub number_of_line_numbers: u16,
        pub characteristics: u32,
    }

    #[repr(C)]
    pub struct ImageExportDirectory {
        pub characteristics: u32,
        pub time_date_stamp: u32,
        pub major_version: u16,
        pub minor_version: u16,
        pub name: u32,
        pub base: u32,
        pub number_of_functions: u32,
        pub number_of_names: u32,
        pub address_of_functions: u32,
        pub address_of_names: u32,
        pub address_of_name_ordinals: u32,
    }

    // -----------------------------------------------------------------------
    // core_impl — PEB walk, gadget scanning, SSN extraction
    // -----------------------------------------------------------------------

    pub mod core_impl {
        use super::*;
        use super::crypto;

        /// Read PEB address from GS:[0x60].
        ///
        /// # Safety
        ///
        /// This function is only valid on the Windows x86-64 target where the
        /// GS:[0x60] PEB location and the inline assembly assumptions hold.
        #[inline(always)]
        pub unsafe fn get_peb() -> *mut u8 {
            let peb: usize;
            unsafe {
                core::arch::asm!(
                    "mov {}, gs:[0x60]",
                    out(reg) peb,
                    options(nostack, preserves_flags, pure, readonly),
                );
            }
            peb as *mut u8
        }

        fn section_base(base: *mut u8) -> (*const ImageSectionHeader, u16) {
            unsafe {
                let dos = base as *const ImageDosHeader;
                let nt = base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;
                let sec = (nt as *const u8)
                    .add(core::mem::size_of::<u32>())
                    .add(core::mem::size_of::<ImageFileHeader>())
                    .add((*nt).file_header.size_of_optional_header as usize)
                    as *const ImageSectionHeader;
                (sec, (*nt).file_header.number_of_sections)
            }
        }

        /// Walk PEB Ldr InLoadOrder list and return a module base by hash of its lowercased name.
        ///
        /// # Safety
        ///
        /// The current process PEB and loader structures must be valid and
        /// readable, as supplied by the Windows x86-64 process environment.
        pub unsafe fn find_module(module_hash: u32) -> *mut u8 {
            let peb = unsafe { get_peb() };
            if peb.is_null() {
                return core::ptr::null_mut();
            }
            let ldr = unsafe { *(peb.add(0x18) as *const *mut u8) };
            let head = unsafe { ldr.add(0x20) } as *mut ListEntry;
            let mut current = unsafe { (*head).flink };

            while current != head {
                let dll_base = unsafe { *(current.cast::<u8>().add(0x20) as *const *mut u8) };
                if !dll_base.is_null() {
                    let name = unsafe { current.cast::<u8>().add(0x48) } as *const UnicodeString;
                    let len = unsafe { (*name).length };
                    if len > 0 && unsafe { crypto::hash_wide((*name).buffer, len) } == module_hash {
                        return dll_base;
                    }
                }
                current = unsafe { (*current).flink };
            }
            core::ptr::null_mut()
        }

        /// True if ntdll's .text section has the write bit set (EDR hook indicator).
        ///
        /// # Safety
        ///
        /// `base` must point to a valid, mapped Windows PE image whose DOS, NT,
        /// and section headers are readable.
        pub unsafe fn is_text_writable(base: *mut u8) -> bool {
            if base.is_null() {
                return false;
            }
            let (sec_base, count) = unsafe { section_base(base) };
            for i in 0..count as usize {
                let sec = unsafe { &*sec_base.add(i) };
                if u32::from_le_bytes(sec.name[..4].try_into().unwrap()) == 0x7865742E {
                    return (sec.characteristics & 0x8000_0000) != 0;
                }
            }
            false
        }

        /// Scan .text for a `syscall; ret` (0F 05 [C3|C2]) gadget.
        ///
        /// # Safety
        ///
        /// `base` must point to a valid, mapped Windows PE image whose DOS, NT,
        /// section headers, and referenced `.text` bytes are readable.
        pub unsafe fn scan_for_gadget(base: *mut u8) -> *mut u8 {
            if base.is_null() {
                return core::ptr::null_mut();
            }
            let (sec_base, count) = unsafe { section_base(base) };
            for i in 0..count as usize {
                let sec = unsafe { &*sec_base.add(i) };
                if u32::from_le_bytes(sec.name[..4].try_into().unwrap()) == 0x7865742E {
                    let text = unsafe { base.add(sec.virtual_address as usize) };
                    let size = sec.virtual_size as usize;
                    if size < 16 {
                        return core::ptr::null_mut();
                    }
                    let mut j = 0usize;
                    while j + 16 <= size {
                        if unsafe { *text.add(j) } == 0x0F && unsafe { *text.add(j + 1) } == 0x05 {
                            let mut k = 2usize;
                            while k < 8 {
                                let op = unsafe { *text.add(j + k) };
                                if op == 0xC3 || op == 0xC2 {
                                    return unsafe { text.add(j) };
                                }
                                if op == 0x58 || op == 0x59 || op == 0x5A || op == 0x5B
                                    || (op == 0x83 && k + 1 < 8 && unsafe { *text.add(j + k + 1) } == 0xC4)
                                {
                                    break;
                                }
                                if op == 0x90 {
                                    k += 1;
                                    continue;
                                }
                                break;
                            }
                        }
                        j += 1;
                    }
                }
            }
            core::ptr::null_mut()
        }

        /// Scan first 64 bytes of a stub for a local `syscall; ret` gadget.
        ///
        /// # Safety
        ///
        /// `func_addr` must point to at least 66 readable bytes of executable
        /// memory so the 64-byte scan can safely inspect each 3-byte candidate.
        pub unsafe fn find_local_gadget(func_addr: *mut u8) -> *mut u8 {
            for i in 0..64usize {
                let p = unsafe { func_addr.add(i) };
                if unsafe { *p } == 0x0F && unsafe { *p.add(1) } == 0x05 {
                    let next = unsafe { *p.add(2) };
                    if next == 0xC3 || next == 0xC2 {
                        return p;
                    }
                }
            }
            core::ptr::null_mut()
        }

        /// Scan .text for a `call reg; ret` proxy gadget.
        /// Sets `reg_index`: 0=rbx 1=rdi 2=rsi 3=r12 4=r13 5=r14 6=r15
        ///
        /// # Safety
        ///
        /// `base` must point to a valid, mapped Windows PE image whose DOS, NT,
        /// section headers, and referenced `.text` bytes are readable.
        /// `reg_index` must be a valid mutable reference for the duration of the call.
        pub unsafe fn find_proxy_gadget(base: *mut u8, reg_index: &mut u32) -> *mut u8 {
            if base.is_null() {
                return core::ptr::null_mut();
            }
            let (sec_base, count) = unsafe { section_base(base) };
            for i in 0..count as usize {
                let sec = unsafe { &*sec_base.add(i) };
                if u32::from_le_bytes(sec.name[..4].try_into().unwrap()) == 0x7865742E {
                    let text = unsafe { base.add(sec.virtual_address as usize) };
                    let size = sec.virtual_size as usize;
                    if size < 4 {
                        return core::ptr::null_mut();
                    }
                    let mut j = 0usize;
                    while j + 4 <= size {
                        if j + 2 >= size {
                            break;
                        }
                        if unsafe { *text.add(j + 2) } == 0xC3 && unsafe { *text.add(j) } == 0xFF {
                            match unsafe { *text.add(j + 1) } {
                                0xD3 => { *reg_index = 0; return unsafe { text.add(j) }; }
                                0xD7 => { *reg_index = 1; return unsafe { text.add(j) }; }
                                0xD6 => { *reg_index = 2; return unsafe { text.add(j) }; }
                                _ => {}
                            }
                        }
                        if j + 3 < size
                            && unsafe { *text.add(j + 3) } == 0xC3
                            && unsafe { *text.add(j) } == 0x41
                            && unsafe { *text.add(j + 1) } == 0xFF
                        {
                            match unsafe { *text.add(j + 2) } {
                                0xD4 => { *reg_index = 3; return unsafe { text.add(j) }; }
                                0xD5 => { *reg_index = 4; return unsafe { text.add(j) }; }
                                0xD6 => { *reg_index = 5; return unsafe { text.add(j) }; }
                                0xD7 => { *reg_index = 6; return unsafe { text.add(j) }; }
                                _ => {}
                            }
                        }
                        j += 1;
                    }
                }
            }
            core::ptr::null_mut()
        }

        /// Extract SSN directly from stub bytes.
        ///
        /// # Safety
        ///
        /// `func` must point to at least 28 readable bytes containing a Windows
        /// x86-64 syscall stub.
        pub unsafe fn extract_ssn_direct(func: *const u8) -> u32 {
            if unsafe { *func.add(3) } == 0xB8 {
                return unsafe { core::ptr::read_unaligned(func.add(4) as *const u32) };
            }
            for i in 0..24usize {
                if unsafe { *func.add(i) } == 0xB8 {
                    let val = unsafe { core::ptr::read_unaligned(func.add(i + 1) as *const u32) };
                    if val < 0x1000 {
                        return val;
                    }
                }
            }
            0xFFFF_FFFF
        }

        /// Extract SSN by counting preceding Nt* exports (Halo's Gate fallback).
        ///
        /// # Safety
        ///
        /// `target_addr` and `base` must belong to the same valid, mapped Windows
        /// PE image, and its DOS, NT, export, name, ordinal, function, and string
        /// data referenced by the export directory must be readable.
        pub unsafe fn extract_ssn_sorted(target_addr: *mut u8, base: *mut u8) -> u32 {
            let dos = base as *const ImageDosHeader;
            let nt = unsafe { base.add((*dos).e_lfanew as usize) } as *const ImageNtHeaders64;
            let exp_rva = unsafe { (*nt).optional_header.data_directory[0].virtual_address };
            let exp = unsafe { base.add(exp_rva as usize) } as *const ImageExportDirectory;

            let funcs = unsafe { base.add((*exp).address_of_functions as usize) } as *const u32;
            let names = unsafe { base.add((*exp).address_of_names as usize) } as *const u32;
            let ords = unsafe { base.add((*exp).address_of_name_ordinals as usize) } as *const u16;

            const H_GETTICK: u32 = crypto::hash_str(b"NtGetTickCount");
            const H_QUERYTIME: u32 = crypto::hash_str(b"NtQuerySystemTime");

            let mut ssn: u32 = 0;
            for i in 0..unsafe { (*exp).number_of_names } as usize {
                let name_ptr = unsafe { base.add(*names.add(i) as usize) } as *const u8;
                let addr = unsafe { base.add(*funcs.add(*ords.add(i) as usize) as usize) };
                if unsafe { *name_ptr } == b'N' && unsafe { *name_ptr.add(1) } == b't' {
                    if unsafe { *name_ptr.add(3) } == b'l' {
                        continue;
                    }
                    let h = unsafe { crypto::hash_cstr(name_ptr) };
                    if h == H_GETTICK || h == H_QUERYTIME {
                        continue;
                    }
                    if (addr as usize) < (target_addr as usize) {
                        ssn += 1;
                    }
                }
            }
            ssn
        }
    }

    // -----------------------------------------------------------------------
    // engine — global lazy state + Resolve
    // -----------------------------------------------------------------------

    pub mod engine {
        use super::core_impl;
        use super::*;
        use super::crypto;

        static NTDLL_BASE: SafePtr = SafePtr::new();
        static CLEAN_SITE: SafePtr = SafePtr::new();
        static PROXY_SITE: SafePtr = SafePtr::new();
        static PROXY_REG: AtomicUsize = AtomicUsize::new(0);

        fn ensure_init() -> bool {
            if !NTDLL_BASE.get().is_null() {
                return true;
            }
            unsafe {
                const H_NTDLL: u32 = crypto::hash_str(b"ntdll.dll");
                let base = core_impl::find_module(H_NTDLL);
                if base.is_null() {
                    return false;
                }

                let compromised = core_impl::is_text_writable(base);
                let mut clean: *mut u8 = core::ptr::null_mut();

                if !compromised {
                    clean = core_impl::scan_for_gadget(base);
                }
                if clean.is_null() {
                    const H_W32: u32 = crypto::hash_str(b"win32u.dll");
                    let m = core_impl::find_module(H_W32);
                    if !m.is_null() {
                        clean = core_impl::scan_for_gadget(m);
                    }
                }
                if clean.is_null() {
                    const H_KB: u32 = crypto::hash_str(b"kernelbase.dll");
                    let m = core_impl::find_module(H_KB);
                    if !m.is_null() {
                        clean = core_impl::scan_for_gadget(m);
                    }
                }

                let mut p_reg: u32 = 0;
                let proxy = core_impl::find_proxy_gadget(base, &mut p_reg);

                CLEAN_SITE.set_if_null(clean);
                PROXY_SITE.set_if_null(proxy);
                PROXY_REG.store(p_reg as usize, Ordering::Release);
                core::sync::atomic::fence(Ordering::SeqCst);
                NTDLL_BASE.set_if_null(base);
                true
            }
        }

        /// Resolved call info returned to the syscall! macro.
        #[derive(Copy, Clone, Debug)]
        pub struct TargetInfo {
            pub ssn: u32,
            pub site: *mut u8,
            pub proxy: *mut u8,
            pub reg: u32,
        }

        unsafe impl Send for TargetInfo {}
        unsafe impl Sync for TargetInfo {}

        pub fn resolve(func_hash: u32) -> TargetInfo {
            let null_info = TargetInfo {
                ssn: 0,
                site: core::ptr::null_mut(),
                proxy: core::ptr::null_mut(),
                reg: 0,
            };

            if !ensure_init() {
                return null_info;
            }

            unsafe {
                let base = NTDLL_BASE.get();
                let global_site = CLEAN_SITE.get();
                let proxy = PROXY_SITE.get();
                let proxy_reg = PROXY_REG.load(Ordering::Acquire) as u32;

                let dos = base as *const ImageDosHeader;
                let nt = base.add((*dos).e_lfanew as usize) as *const ImageNtHeaders64;
                let exp_rva = (*nt).optional_header.data_directory[0].virtual_address;
                let exp = base.add(exp_rva as usize) as *const ImageExportDirectory;

                let funcs = base.add((*exp).address_of_functions as usize) as *const u32;
                let names = base.add((*exp).address_of_names as usize) as *const u32;
                let ords = base.add((*exp).address_of_name_ordinals as usize) as *const u16;

                for i in 0..(*exp).number_of_names as usize {
                    let name_ptr = base.add(*names.add(i) as usize) as *const u8;
                    if crypto::hash_cstr(name_ptr) == func_hash {
                        let func_addr = base.add(*funcs.add(*ords.add(i) as usize) as usize);
                        let mut ssn = core_impl::extract_ssn_direct(func_addr);
                        if ssn == 0xFFFF_FFFF {
                            ssn = core_impl::extract_ssn_sorted(func_addr, base);
                        }
                        if ssn == 0xFFFF_FFFF {
                            break;
                        }
                        let local = core_impl::find_local_gadget(func_addr);
                        let site = if !local.is_null() { local } else { global_site };
                        return TargetInfo { ssn, site, proxy, reg: proxy_reg };
                    }
                }
                null_info
            }
        }
    }

    // -----------------------------------------------------------------------
    // invoke — naked x64 stub
    // -----------------------------------------------------------------------
    //
    // Windows x64 fastcall on entry:
    //   ecx  = ssn
    //   rdx  = site   (*mut u8)
    //   r8   = proxy  (*mut u8, may be null)
    //   r9d  = reg    (u32 — which callee-saved reg holds the site ptr)
    //   [rsp+0x28] = args (*mut usize, flat array of up to 12 NT args)

    extern "C" {
        pub fn do_syscall_invoke(
            ssn: u32,
            site: *mut u8,
            proxy: *mut u8,
            reg: u32,
            args: *mut usize,
        ) -> i32;
    }

    core::arch::global_asm!(
        ".global do_syscall_invoke",
        ".section .text",
        "do_syscall_invoke:",

        "push rbx",
        "push rdi",
        "push rsi",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "push rbp",

        // obfuscation nop loop: (ssn * 3) & 0xF iterations
        "xor eax, eax",
        "add eax, ecx",
        "imul eax, eax, 3",
        "and eax, 0x0F",
        "jz 2f",
        "1:",
        "nop",
        "sub eax, 1",
        "jnz 1b",
        "2:",

        "mov rax, rdx",
        "mov r11, r8",

        // dispatch site ptr into the callee-saved reg chosen by r9d
        "cmp r9d, 0",  "je 10f",
        "cmp r9d, 1",  "je 11f",
        "cmp r9d, 2",  "je 12f",
        "cmp r9d, 3",  "je 13f",
        "cmp r9d, 4",  "je 14f",
        "cmp r9d, 5",  "je 15f",
        "cmp r9d, 6",  "je 16f",
        "jmp 10f",

        "16:", "mov r15, rax", "jmp 20f",
        "15:", "mov r14, rax", "jmp 20f",
        "14:", "mov r13, rax", "jmp 20f",
        "13:", "mov r12, rax", "jmp 20f",
        "12:", "mov rsi, rax", "jmp 20f",
        "11:", "mov rdi, rax", "jmp 20f",
        "10:", "mov rbx, rax",

        "20:",
        // 8 pushes above = 0x40; original 5th param at [rsp+0x28] is now at [rsp+0x68]
        "mov r10, [rsp + 0x68]",
        "push r10",
        "sub rsp, 0x68",

        // zero shadow space (first 32 bytes)
        "xor rax, rax",
        "mov [rsp], rax",
        "mov [rsp+8], rax",
        "mov [rsp+16], rax",
        "mov [rsp+24], rax",

        // copy args[4..11] into stack slots (NT args beyond the 4 register args)
        "mov rax, [r10 + 32]",  "mov [rsp + 0x10], rax",
        "mov rax, [r10 + 40]",  "mov [rsp + 0x18], rax",
        "mov rax, [r10 + 48]",  "mov [rsp + 0x20], rax",
        "mov rax, [r10 + 56]",  "mov [rsp + 0x28], rax",
        "mov rax, [r10 + 64]",  "mov [rsp + 0x30], rax",
        "mov rax, [r10 + 72]",  "mov [rsp + 0x38], rax",
        "mov rax, [r10 + 80]",  "mov [rsp + 0x40], rax",
        "mov rax, [r10 + 88]",  "mov [rsp + 0x48], rax",

        // load NT register args and SSN
        "mov eax, ecx",
        "mov rdx, [r10 + 8]",
        "mov r8,  [r10 + 16]",
        "mov r9,  [r10 + 24]",
        "mov r10, [r10]",

        // indirect via proxy, or direct
        "test r11, r11",
        "jz 30f",
        "call r11",
        "jmp 40f",

        "30:",
        "sub rsp, 16",
        "call rbx",
        "add rsp, 16",

        "40:",
        // scrub stack
        "xor rax, rax",
        "mov [rsp + 0x10], rax",
        "mov [rsp + 0x18], rax",
        "mov [rsp + 0x20], rax",
        "mov [rsp + 0x28], rax",
        "mov [rsp + 0x30], rax",
        "mov [rsp + 0x38], rax",
        "mov [rsp + 0x40], rax",
        "mov [rsp + 0x48], rax",

        "xor r11, r11",
        "xor r10, r10",
        "xor r9d, r9d",

        "add rsp, 0x68",
        "pop r10",
        "pop rbp",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rsi",
        "pop rdi",
        "pop rbx",
        "ret",
    );

    /// Invoke wrapper: builds an arg array and calls the stub.
    /// `args` must have at most 12 elements.
    ///
    /// # Safety
    ///
    /// `info` must describe valid syscall dispatch addresses/register state for
    /// the Windows x86-64 invocation stub. `args` must contain only values valid
    /// for the target syscall's parameter contract.
    pub unsafe fn invoke(info: engine::TargetInfo, args: &[usize]) -> i32 {
        let mut arr = [0usize; 12];
        let n = args.len().min(12);
        arr[..n].copy_from_slice(&args[..n]);
        unsafe { do_syscall_invoke(info.ssn, info.site, info.proxy, info.reg, arr.as_mut_ptr()) }
    }
}

// Re-export the public API on Windows x64.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub use windows_impl::core_impl;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub use windows_impl::engine;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub use windows_impl::invoke;

// ---------------------------------------------------------------------------
// syscall! macro — Windows x64 only at runtime
// ---------------------------------------------------------------------------

/// Resolve and invoke an NT syscall by name (hashed at compile time).
///
/// ```ignore
/// let status = syscall!("NtClose", handle as usize);
/// ```
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[macro_export]
macro_rules! syscall {
    ($name:literal $(, $arg:expr)*) => {{
        const _H: u32 = crate::syscalls::crypto::hash_str($name.as_bytes());
        let _info = crate::syscalls::engine::resolve(_H);
        if _info.site.is_null() {
            0xC000_0002_u32 as i32 // STATUS_NOT_IMPLEMENTED
        } else {
            let _args: &[usize] = &[$($arg as usize),*];
            unsafe { crate::syscalls::invoke(_info, _args) }
        }
    }};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
