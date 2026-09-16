use std::collections::HashMap;

#[cfg(windows)]
mod win {
    use super::*;
    use crate::{syscall, text, update};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::mpsc::{self, Receiver, Sender};

    // NT constants
    const MEM_COMMIT: usize    = 0x1000;
    const MEM_RESERVE: usize   = 0x2000;
    const MEM_RELEASE: usize   = 0x8000;
    const PAGE_RW: usize       = 0x04;
    const PAGE_RX: usize       = 0x20;
    const PAGE_RWX: usize      = 0x40;
    const CURRENT_PROC: usize  = usize::MAX; // NtCurrentProcess()

    type Emit = unsafe extern "C" fn(*const u8, u32, *const u8, u32) -> i32;
    type OnLoad   = unsafe extern "C" fn(*const u8, u32, Emit) -> i32;
    type OnEvent  = unsafe extern "C" fn(*const u8, u32, *const u8, u32) -> i32;
    type OnUnload = unsafe extern "C" fn();

    // Minimal PE parsing
    #[repr(C)] struct DosHdr { e_magic: u16, _pad: [u8; 58], e_lfanew: i32 }
    #[repr(C)] struct FileHdr { machine: u16, sections: u16, _ts: u32, _sym: u32, _nsym: u32, opt_sz: u16, chars: u16 }
    #[repr(C)] struct DataDir { va: u32, size: u32 }
    #[repr(C)] struct OptHdr64 {
        magic: u16, _mj: u8, _mn: u8, _code: u32, _idata: u32, _udata: u32,
        entry: u32, _bcode: u32, image_base: u64, sec_align: u32, file_align: u32,
        _osmj: u16, _osmn: u16, _imj: u16, _imn: u16, _ssmj: u16, _ssmn: u16,
        _w32: u32, image_sz: u32, hdr_sz: u32, _ck: u32, subsys: u16, _dll: u16,
        _sr: u64, _sc: u64, _hr: u64, _hc: u64, _lf: u32, rva_count: u32,
        dirs: [DataDir; 16],
    }
    #[repr(C)] struct NtHdrs64 { sig: u32, file: FileHdr, opt: OptHdr64 }
    #[repr(C)] struct SecHdr { name: [u8; 8], vsize: u32, va: u32, raw_sz: u32, raw_off: u32, _r: [u8; 12], chars: u16, _pad: u16 }
    #[repr(C)] struct ExpDir { _chars: u32, _ts: u32, _mj: u16, _mn: u16, _name: u32, base: u32, n_fns: u32, n_names: u32, fn_off: u32, name_off: u32, ord_off: u32 }
    #[repr(C)] struct BaseReloc { va: u32, sz: u32 }
    #[repr(C)] struct ImportDesc { orig_thunk: u32, _ts: u32, _fwd: u32, name: u32, thunk: u32 }
    #[repr(C)] struct ImportByName { hint: u16, name: [u8; 1] }

    unsafe fn nt_alloc(size: usize, prot: usize) -> *mut u8 {
        let mut base: usize = 0;
        let mut sz = size;
        let s = syscall!("NtAllocateVirtualMemory",
            CURRENT_PROC, &mut base as *mut usize as usize,
            0usize, &mut sz as *mut usize as usize,
            MEM_COMMIT | MEM_RESERVE, prot);
        if s < 0 { core::ptr::null_mut() } else { base as *mut u8 }
    }

    unsafe fn nt_protect(base: *mut u8, size: usize, prot: usize) -> bool {
        let mut old = 0usize;
        let mut sz = size;
        let mut b = base as usize;
        syscall!("NtProtectVirtualMemory",
            CURRENT_PROC, &mut b as *mut usize as usize,
            &mut sz as *mut usize as usize, prot, &mut old as *mut usize as usize) >= 0
    }

    unsafe fn nt_free(base: *mut u8, size: usize) {
        let mut b = base as usize;
        let mut sz = size;
        syscall!("NtFreeVirtualMemory",
            CURRENT_PROC, &mut b as *mut usize as usize,
            &mut sz as *mut usize as usize, MEM_RELEASE);
    }

    // resolve an export by ASCII name from an already-mapped image
    unsafe fn get_export(image: *mut u8, name: &str) -> Option<*mut u8> {
        let dos = unsafe { &*(image as *const DosHdr) };
        let nt  = unsafe { &*(image.add(dos.e_lfanew as usize) as *const NtHdrs64) };
        let exp_rva = nt.opt.dirs[0].va as usize;
        if exp_rva == 0 { return None; }
        let exp = unsafe { &*(image.add(exp_rva) as *const ExpDir) };
        let fns   = unsafe { image.add(exp.fn_off as usize) } as *const u32;
        let names = unsafe { image.add(exp.name_off as usize) } as *const u32;
        let ords  = unsafe { image.add(exp.ord_off as usize) } as *const u16;
        let want  = name.as_bytes();
        for i in 0..exp.n_names as usize {
            let nptr = unsafe { image.add(*names.add(i) as usize) };
            let mut ok = true;
            for (j, &b) in want.iter().enumerate() {
                if unsafe { *nptr.add(j) } != b { ok = false; break; }
            }
            if ok && unsafe { *nptr.add(want.len()) } == 0 {
                let ord = unsafe { *ords.add(i) } as usize;
                let rva = unsafe { *fns.add(ord) } as usize;
                return Some(unsafe { image.add(rva) });
            }
        }
        None
    }

    // Resolve an export, following PE forwarded-export strings such as
    // "KERNELBASE.GetEnvironmentVariableA" to the loaded target module.
    unsafe fn resolve_export(image: *mut u8, name: &str, depth: u32) -> Option<*mut u8> {
        if image.is_null() || depth >= 8 {
            return None;
        }

        let dos = unsafe { &*(image as *const DosHdr) };
        let nt  = unsafe { &*(image.add(dos.e_lfanew as usize) as *const NtHdrs64) };
        let exp_rva = nt.opt.dirs[0].va as usize;
        let exp_size = nt.opt.dirs[0].size as usize;
        let addr = unsafe { get_export(image, name)? };

        let addr_rva = (addr as usize).wrapping_sub(image as usize);
        if addr_rva < exp_rva || addr_rva >= exp_rva.saturating_add(exp_size) {
            return Some(addr);
        }

        let mut len = 0usize;
        while len < exp_size && unsafe { *addr.add(len) } != 0 {
            len += 1;
        }
        if len == exp_size {
            return None;
        }

        let forwarder = unsafe { core::slice::from_raw_parts(addr, len) };
        let forwarder = core::str::from_utf8(forwarder).ok()?;
        let (module, symbol) = forwarder.split_once('.')?;

        use crate::syscalls::core_impl;
        use crate::syscalls::crypto;

        let module_name = if module.to_ascii_lowercase().ends_with(".dll") {
            module.to_ascii_lowercase()
        } else {
            format!("{module}.dll").to_ascii_lowercase()
        };
        let module_hash = crypto::hash_str(module_name.as_bytes());
        let base = unsafe { core_impl::find_module(module_hash) };
        if base.is_null() {
            return None;
        }

        unsafe { resolve_export(base, symbol, depth + 1) }
    }

    // Resolve imported functions from the process loader list.
    unsafe fn resolve_import(mod_name: &[u8], fn_name: &[u8]) -> Option<*mut u8> {
        use crate::syscalls::core_impl;
        use crate::syscalls::crypto;

        let h = crypto::hash_str(mod_name);
        let base = unsafe { core_impl::find_module(h) };
        if base.is_null() { return None; }

        unsafe { resolve_export(base, core::str::from_utf8(fn_name).ok()?, 0) }
    }

    // Manual PE loader: maps image, applies relocs, resolves imports, sets protections
    unsafe fn load_pe(data: &[u8]) -> Option<(*mut u8, usize)> {
        if data.len() < 64 { return None; }
        let dos = unsafe { &*(data.as_ptr() as *const DosHdr) };
        if dos.e_magic != 0x5A4D { return None; }
        let nt_off = dos.e_lfanew as usize;
        if nt_off + core::mem::size_of::<NtHdrs64>() > data.len() { return None; }
        let nt = unsafe { &*(data.as_ptr().add(nt_off) as *const NtHdrs64) };
        if nt.sig != 0x0004550 || nt.opt.magic != 0x020B { return None; }

        let image_sz = nt.opt.image_sz as usize;
        let hdr_sz   = nt.opt.hdr_sz as usize;
        let image = unsafe { nt_alloc(image_sz, PAGE_RW) };
        if image.is_null() { return None; }

        // Copy headers
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), image, hdr_sz.min(data.len())) };

        // Copy sections
        let sec_base = unsafe {
            data.as_ptr().add(nt_off)
                .add(core::mem::size_of::<u32>())
                .add(core::mem::size_of::<FileHdr>())
                .add(nt.file.opt_sz as usize)
        } as *const SecHdr;
        let n_sec = nt.file.sections as usize;
        for i in 0..n_sec {
            let s = unsafe { &*sec_base.add(i) };
            if s.raw_sz == 0 { continue; }
            let src = s.raw_off as usize;
            let dst = s.va as usize;
            let sz  = s.raw_sz as usize;
            if src + sz > data.len() || dst + sz > image_sz { continue; }
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr().add(src), image.add(dst), sz) };
        }

        // Apply base relocations
        let pref_base = nt.opt.image_base as usize;
        let actual    = image as usize;
        let delta     = actual.wrapping_sub(pref_base) as isize;
        if delta != 0 {
            let reloc_dir = &nt.opt.dirs[5];
            if reloc_dir.size > 0 {
                let mut off = reloc_dir.va as usize;
                let end = off + reloc_dir.size as usize;
                while off < end {
                    let blk = unsafe { &*(image.add(off) as *const BaseReloc) };
                    if blk.sz < 8 { break; }
                    let page_va = blk.va as usize;
                    let n_ent   = (blk.sz as usize - 8) / 2;
                    let entries = unsafe { image.add(off + 8) } as *const u16;
                    for j in 0..n_ent {
                        let e = unsafe { *entries.add(j) };
                        let typ = (e >> 12) as u32;
                        let o   = (e & 0x0FFF) as usize;
                        if typ == 10 { // IMAGE_REL_BASED_DIR64
                            let ptr = unsafe { image.add(page_va + o) } as *mut isize;
                            unsafe { *ptr = (*ptr).wrapping_add(delta) };
                        }
                    }
                    off += blk.sz as usize;
                }
            }
        }

        // Resolve imports. Every imported function must resolve: a null IAT
        // entry would only move the failure from load time to the first call.
        let imp_dir = &nt.opt.dirs[1];
        if imp_dir.size > 0 {
            let mut imp_off = imp_dir.va as usize;
            loop {
                let desc = unsafe { &*(image.add(imp_off) as *const ImportDesc) };
                if desc.name == 0 { break; }
                let mod_name_ptr = unsafe { image.add(desc.name as usize) };
                let mut mod_len = 0usize;
                while unsafe { *mod_name_ptr.add(mod_len) } != 0 { mod_len += 1; }
                let mod_name_lc: Vec<u8> = unsafe { core::slice::from_raw_parts(mod_name_ptr, mod_len) }
                    .iter().map(|b| b.to_ascii_lowercase()).collect();

                let thunk_off = if desc.orig_thunk != 0 { desc.orig_thunk } else { desc.thunk } as usize;
                let iat_off   = desc.thunk as usize;
                let mut k = 0usize;
                loop {
                    let thunk = unsafe { *(image.add(thunk_off + k * 8) as *const usize) };
                    if thunk == 0 { break; }
                    let fn_addr = if thunk & (1 << 63) != 0 {
                        // Ordinal imports are not used by the bundled plugin ABI.
                        None
                    } else {
                        let ibn = unsafe { image.add(thunk & 0x7FFF_FFFF_FFFF_FFFF) } as *const ImportByName;
                        let fn_name_ptr = unsafe { (*ibn).name.as_ptr() };
                        let mut fn_len = 0usize;
                        while unsafe { *fn_name_ptr.add(fn_len) } != 0 { fn_len += 1; }
                        let fn_bytes = unsafe { core::slice::from_raw_parts(fn_name_ptr, fn_len) };
                        unsafe { resolve_import(&mod_name_lc, fn_bytes) }
                    };
                    let Some(fn_addr) = fn_addr else {
                        unsafe { nt_free(image, image_sz); }
                        return None;
                    };
                    unsafe { *(image.add(iat_off + k * 8) as *mut usize) = fn_addr as usize; }
                    k += 1;
                }
                imp_off += core::mem::size_of::<ImportDesc>();
            }
        }

        // Set section protections
        for i in 0..n_sec {
            let s = unsafe { &*sec_base.add(i) };
            if s.raw_sz == 0 { continue; }
            let exec  = s.chars & 0x20 != 0;
            let write = s.chars & 0x80 != 0;
            let prot = match (exec, write) {
                (true,  true)  => PAGE_RWX,
                (true,  false) => PAGE_RX,
                (false, true)  => PAGE_RW,
                _              => 0x02, // PAGE_READONLY
            };
            let _ = unsafe { nt_protect(image.add(s.va as usize), s.vsize as usize, prot) };
        }

        Some((image, image_sz))
    }

    pub struct Plugin {
        image:    *mut u8,
        image_sz: usize,
        unload:   OnUnload,
        event:    OnEvent,
    }

    unsafe impl Send for Plugin {}

    impl Drop for Plugin {
        fn drop(&mut self) {
            unsafe {
                (self.unload)();
                nt_free(self.image, self.image_sz);
            }
        }
    }

    struct PluginTransfer {
        id: String,
        path: std::path::PathBuf,
        size: u64,
        hash: String,
        received: u64,
    }

    fn safe_transfer_component(value: &str) -> Option<String> {
        if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return None;
        }
        Some(value.to_owned())
    }

    #[derive(Clone)]
    pub struct PluginOutput {
        pub event: String,
        pub payload: Vec<u8>,
    }

    pub struct Manager {
        map: HashMap<String, Plugin>,
        transfers: HashMap<String, PluginTransfer>,
        rx: Receiver<PluginOutput>,
    }

    impl Manager {
        pub fn new() -> Self {
            let (tx, rx) = mpsc::channel();
            set_emit_sender(tx.clone());
            Self { map: HashMap::new(), transfers: HashMap::new(), rx }
        }

        // Load a plugin from raw DLL bytes supplied in-memory (no disk path).
        pub fn load(&mut self, id: &str, data: &[u8], host: &[u8]) -> Result<(), String> {
            if id.is_empty() { return Err(text::PLUG_ERR_NAME.into()); }

            let (image, image_sz) = unsafe {
                load_pe(data).ok_or_else(|| text::PLUG_ERR_LOAD.to_owned())?
            };

            let on_load   = unsafe { resolve_export(image, "PluginOnLoad", 0) };
            let on_event  = unsafe { resolve_export(image, "PluginOnEvent", 0) };
            let on_unload = unsafe { resolve_export(image, "PluginOnUnload", 0) };
            let (Some(on_load), Some(on_event), Some(on_unload)) =
                (on_load, on_event, on_unload)
            else {
                unsafe { nt_free(image, image_sz); }
                return Err(text::PLUG_ERR_ENTRY.into());
            };

            let load_fn: OnLoad   = unsafe { core::mem::transmute(on_load) };
            let event_fn: OnEvent = unsafe { core::mem::transmute(on_event) };
            let unload_fn: OnUnload = unsafe { core::mem::transmute(on_unload) };

            let ret = unsafe { load_fn(host.as_ptr(), host.len() as u32, emit) };
            if ret != 0 {
                unsafe { nt_free(image, image_sz); }
                return Err(text::PLUG_ERR_INIT.into());
            }

            let new_plugin = Plugin { image, image_sz, unload: unload_fn, event: event_fn };
            if let Some(old_plugin) = self.map.insert(id.to_owned(), new_plugin) {
                drop(old_plugin);
            }
            Ok(())
        }

        pub fn begin_transfer(&mut self, id: &str, transfer_id: &str, size: u64, hash: &str) -> Result<u64, String> {
            let safe_id = safe_transfer_component(id).ok_or_else(|| "invalid plugin id".to_string())?;
            let safe_transfer = safe_transfer_component(transfer_id).ok_or_else(|| "invalid plugin transfer id".to_string())?;
            if size == 0 || size > 256 * 1024 * 1024 || !crate::update::validate_hash(hash, hash) {
                return Err("invalid plugin transfer metadata".into());
            }
            let base = std::env::temp_dir().join("ztsec_plugin_transfers");
            fs::create_dir_all(&base).map_err(|e| e.to_string())?;
            let path = base.join(format!("{}-{}.part", safe_id, safe_transfer));
            let received = match fs::metadata(&path) {
                Ok(m) if m.len() <= size => m.len(),
                Ok(_) => {
                    let file = OpenOptions::new().write(true).truncate(true).open(&path).map_err(|e| e.to_string())?;
                    drop(file);
                    0
                }
                Err(_) => 0,
            };
            if !path.exists() { File::create(&path).map_err(|e| e.to_string())?; }
            self.transfers.insert(transfer_id.to_owned(), PluginTransfer { id: id.to_owned(), path, size, hash: hash.to_ascii_lowercase(), received });
            Ok(received)
        }

        pub fn append_transfer(&mut self, transfer_id: &str, offset: u64, data: &[u8]) -> Result<u64, String> {
            let tr = self.transfers.get_mut(transfer_id).ok_or_else(|| "unknown plugin transfer".to_string())?;
            if offset.saturating_add(data.len() as u64) > tr.size { return Err("invalid plugin chunk offset".into()); }
            if offset < tr.received {
                if offset.saturating_add(data.len() as u64) <= tr.received { return Ok(tr.received); }
                return Err("plugin chunk overlaps committed data".into());
            }
            if offset != tr.received { return Err("invalid plugin chunk offset".into()); }
            let mut f = OpenOptions::new().write(true).open(&tr.path).map_err(|e| e.to_string())?;
            f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
            f.write_all(data).map_err(|e| e.to_string())?;
            tr.received += data.len() as u64;
            Ok(tr.received)
        }

        pub fn finish_transfer(&mut self, transfer_id: &str, host: &[u8]) -> Result<String, String> {
            // Take an owned snapshot before calling `self.load`, which mutably borrows
            // the manager. Keeping `tr` borrowed across that call triggers E0502.
            let (id, path, size, hash, received) = {
                let tr = self.transfers.get(transfer_id).ok_or_else(|| "unknown plugin transfer".to_string())?;
                (tr.id.clone(), tr.path.clone(), tr.size, tr.hash.clone(), tr.received)
            };
            if received != size { return Err("plugin transfer incomplete".into()); }
            let bytes = fs::read(&path).map_err(|e| e.to_string())?;
            if bytes.len() as u64 != size || !update::validate_hash(&hash, &update::sha256_hex(&bytes)) {
                return Err("plugin transfer hash mismatch".into());
            }
            self.load(&id, &bytes, host)?;
            self.transfers.remove(transfer_id);
            let _ = fs::remove_file(path);
            Ok(id)
        }

        pub fn resume_transfer(&self, transfer_id: &str) -> Option<u64> { self.transfers.get(transfer_id).map(|t| t.received) }

        pub fn drain_outputs(&mut self) -> Vec<PluginOutput> {
            self.rx.try_iter().collect()
        }

        pub fn event(&self, event: &str, payload: &[u8]) {
            for p in self.map.values() {
                let _ = unsafe {
                    (p.event)(event.as_ptr(), event.len() as u32, payload.as_ptr(), payload.len() as u32)
                };
            }
        }

        pub fn event_one(&self, id: &str, event: &str, payload: &[u8]) -> Result<(), String> {
            let plugin = self.map.get(id).ok_or_else(|| text::PLUG_ERR_LOAD.to_owned())?;
            let rc = unsafe {
                (plugin.event)(event.as_ptr(), event.len() as u32, payload.as_ptr(), payload.len() as u32)
            };
            if rc == 0 { Ok(()) } else { Err("plugin event rejected".into()) }
        }

        pub fn unload(&mut self, id: &str) -> bool { self.map.remove(id).is_some() }
        pub fn clear(&mut self) { self.map.clear(); self.transfers.clear(); }
    }

    static EMIT_SENDER: std::sync::OnceLock<std::sync::Mutex<Option<Sender<PluginOutput>>>> = std::sync::OnceLock::new();

    fn set_emit_sender(tx: Sender<PluginOutput>) {
        let cell = EMIT_SENDER.get_or_init(|| std::sync::Mutex::new(None));
        if let Ok(mut guard) = cell.lock() { *guard = Some(tx); }
    }

    unsafe extern "C" fn emit(event: *const u8, event_len: u32, payload: *const u8, payload_len: u32) -> i32 {
        let ev = if event.is_null() || event_len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(event, event_len as usize) } };
        let pl = if payload.is_null() || payload_len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(payload, payload_len as usize) } };
        let output = PluginOutput { event: String::from_utf8_lossy(ev).into_owned(), payload: pl.to_vec() };
        if let Some(cell) = EMIT_SENDER.get() {
            if let Ok(guard) = cell.lock() { if let Some(tx) = guard.as_ref() { let _ = tx.send(output); return 0; } }
        }
        -1
    }

    #[cfg(test)]
    mod tests {
        use super::safe_transfer_component;

        #[test]
        fn transfer_component_rejects_path_traversal() {
            assert!(safe_transfer_component("../evil").is_none());
            assert!(safe_transfer_component("..\\evil").is_none());
            assert!(safe_transfer_component("ok-plugin_01").is_some());
        }
    }

    pub use Manager as Host;
}

#[cfg(windows)]
pub use win::Host;

#[cfg(not(windows))]
pub struct Host;

#[cfg(not(windows))]
impl Host {
    pub fn new() -> Self { Self }
    pub fn load(&mut self, _id: &str, _data: &[u8], _host: &[u8]) -> Result<(), String> { Err("windows only".into()) }
    pub fn event(&self, _: &str, _: &[u8]) {}
    pub fn unload(&mut self, _: &str) -> bool { false }
    pub fn clear(&mut self) {}

}

pub use Host as Manager;
