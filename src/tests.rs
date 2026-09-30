use super::crypto;
use super::SafePtr;

#[test]
fn hash_str_deterministic() {
    let a = crypto::hash_str(b"NtAllocateVirtualMemory");
    let b = crypto::hash_str(b"NtAllocateVirtualMemory");
    assert_eq!(a, b);
}

#[test]
fn hash_str_differs() {
    let a = crypto::hash_str(b"NtAllocateVirtualMemory");
    let b = crypto::hash_str(b"NtFreeVirtualMemory");
    assert_ne!(a, b);
}

#[test]
fn hash_str_empty() {
    // Must not panic; result is just the initial state.
    let _ = crypto::hash_str(b"");
}

#[test]
fn hash_macro_matches_hash_str() {
    const H: u32 = crate::syscalls::crypto::hash_str(b"NtClose");
    let runtime = crypto::hash_str(b"NtClose");
    assert_eq!(H, runtime);
}

#[test]
fn safe_ptr_null_on_init() {
    let p = SafePtr::new();
    assert!(p.get().is_null());
}

#[test]
fn safe_ptr_set_and_get() {
    let p = SafePtr::new();
    let val = 0xDEAD_BEEF_usize as *mut u8;
    assert!(p.set_if_null(val));
    assert_eq!(p.get(), val);
}

#[test]
fn safe_ptr_set_if_null_only_once() {
    let p = SafePtr::new();
    let a = 0x1000_usize as *mut u8;
    let b = 0x2000_usize as *mut u8;
    assert!(p.set_if_null(a));
    assert!(!p.set_if_null(b));
    assert_eq!(p.get(), a);
}
