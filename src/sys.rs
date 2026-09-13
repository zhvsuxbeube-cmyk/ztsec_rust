#[cfg(windows)]
mod win {
    use std::{ffi::OsStr, iter, os::windows::ffi::OsStrExt, ptr};

    type Handle = *mut core::ffi::c_void;
    type Status = i32;

    #[repr(C)]
    struct Unicode { len: u16, max: u16, buf: *mut u16 }
    #[repr(C)]
    struct Attrs {
        len: u32, root: Handle, name: *mut Unicode, attrs: u32,
        sd: *mut core::ffi::c_void, qos: *mut core::ffi::c_void,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateMutant(handle: *mut Handle, access: u32, attrs: *mut Attrs, owner: u8) -> Status;
        fn RtlAdjustPrivilege(privilege: u32, enable: u8, thread: u8, previous: *mut u8) -> Status;
        fn NtSetSystemPowerState(action: i32, state: i32, flags: u32) -> Status;
        fn NtShutdownSystem(action: i32) -> Status;
    }

    const OK: Status = 0;
    const ACCESS: u32 = 0x001F0001;
    const SHUTDOWN: u32 = 19;
    const SLEEP: i32 = 2;
    const HIBERNATE: i32 = 3;
    const REBOOT: i32 = 1;
    const POWER_OFF: i32 = 2;
    const S3: i32 = 4;
    const S4: i32 = 5;

    pub fn single() -> bool {
        let wide: Vec<u16> = OsStr::new(crate::text::MUTEX).encode_wide().chain(iter::once(0)).collect();
        let mut name = Unicode { len: ((wide.len() - 1) * 2) as u16, max: (wide.len() * 2) as u16, buf: wide.as_ptr() as *mut u16 };
        let mut attrs = Attrs {
            len: core::mem::size_of::<Attrs>() as u32, root: ptr::null_mut(), name: &mut name,
            attrs: 0, sd: ptr::null_mut(), qos: ptr::null_mut(),
        };
        let mut handle: Handle = ptr::null_mut();
        unsafe { NtCreateMutant(&mut handle, ACCESS, &mut attrs, 0) == OK }
    }

    fn privilege() -> bool {
        let mut previous = 0u8;
        unsafe { RtlAdjustPrivilege(SHUTDOWN, 1, 0, &mut previous) == OK }
    }

    fn power(action: i32, state: i32) -> bool { privilege() && unsafe { NtSetSystemPowerState(action, state, 0) == OK } }

    pub fn command(cmd: &str) -> bool {
        match cmd {
            crate::text::SLEEP => power(SLEEP, S3),
            crate::text::HIBERNATE => power(HIBERNATE, S4),
            crate::text::RESTART if privilege() => unsafe { NtShutdownSystem(REBOOT) == OK },
            crate::text::SHUTDOWN if privilege() => unsafe { NtShutdownSystem(POWER_OFF) == OK },
            _ => false,
        }
    }
}

#[cfg(not(windows))]
mod win {
    pub fn single() -> bool { true }
    pub fn command(_: &str) -> bool { false }
}

pub use win::{command, single};
