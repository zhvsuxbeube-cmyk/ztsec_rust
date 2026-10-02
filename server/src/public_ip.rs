use std::{io, net::{IpAddr, SocketAddr}, time::Duration};


const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BODY_BYTES: usize = 128;
const PRIMARY_URL: &str = "https://ifconfig.me/ip";
const IPV4_URL: &str = "https://ipv4.ifconfig.me/ip";
const IPV6_URL: &str = "https://ipv6.ifconfig.me/ip";

/// Resolve the public address advertised for the server's built-in direct listener.
/// The destination is fixed to ifconfig.me; callers cannot provide an arbitrary lookup URL.
pub async fn resolve_public_ip(listen_addr: SocketAddr) -> io::Result<IpAddr> {
    if let Some(test_value) = std::env::var_os("ZTSEC_TEST_PUBLIC_IP") {
        if std::env::var_os("ZTSEC_CI").is_some() {
            let value = test_value.to_string_lossy();
            let ip = value.trim().parse::<IpAddr>().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid ZTSEC_TEST_PUBLIC_IP"))?;
            validate_family(ip, listen_addr, true)?;
            return Ok(ip);
        }
    }

    // ifconfig.me is the authoritative public-IP source. Family-specific endpoints are
    // fallback paths when the generic endpoint returns an address of the wrong family.
    match fetch_ip(PRIMARY_URL, listen_addr).await {
        Ok(ip) => Ok(ip),
        Err(primary_error) => {
            let family_url = match listen_addr {
                SocketAddr::V4(_) => IPV4_URL,
                SocketAddr::V6(_) => IPV6_URL,
            };
            fetch_ip(family_url, listen_addr).await.map_err(|fallback_error| {
                io::Error::new(io::ErrorKind::Other, format!("ifconfig.me lookup failed: {primary_error}; family-specific fallback failed: {fallback_error}"))
            })
        }
    }
}

async fn fetch_ip(url: &str, listen_addr: SocketAddr) -> io::Result<IpAddr> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(REQUEST_TIMEOUT)
        .user_agent("ztsec-server/1")
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("build IP lookup client: {e}")))?;

    let mut response = client.get(url).send().await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("request {url}: {e}")))?
        .error_for_status()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("IP lookup response: {e}")))?;

    if response.content_length().is_some_and(|len| len > MAX_BODY_BYTES as u64) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "IP lookup response is too large"));
    }
    let mut body = Vec::with_capacity(MAX_BODY_BYTES);
    while let Some(chunk) = response.chunk().await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("read IP lookup response: {e}")))? {
        if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "IP lookup response exceeded size limit"));
        }
        body.extend_from_slice(&chunk);
    }
    let text = std::str::from_utf8(&body).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "IP lookup response is not UTF-8"))?;
    let ip = text.trim().parse::<IpAddr>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "IP lookup response is not an IP address"))?;
    validate_family(ip, listen_addr, false)?;
    Ok(ip)
}

fn validate_family(ip: IpAddr, listen_addr: SocketAddr, allow_loopback_for_test: bool) -> io::Result<()> {
    let is_link_local = match ip {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.is_unicast_link_local(),
    };
    if ip.is_unspecified() || ip.is_multicast() || is_link_local || (!allow_loopback_for_test && ip.is_loopback()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "public IP lookup returned a non-publicly-routable address"));
    }
    if matches!((ip, listen_addr), (IpAddr::V4(_), SocketAddr::V6(_)) | (IpAddr::V6(_), SocketAddr::V4(_))) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "public IP family does not match direct listener"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loopback_test_ip() {
        let listen: SocketAddr = "0.0.0.0:4794".parse().unwrap();
        assert!(validate_family("127.0.0.1".parse().unwrap(), listen, false).is_err());
        assert!(validate_family("127.0.0.1".parse().unwrap(), listen, true).is_ok());
    }

    #[test]
    fn rejects_mismatched_family() {
        let listen: SocketAddr = "[::]:4794".parse().unwrap();
        assert!(validate_family("203.0.113.10".parse().unwrap(), listen, false).is_err());
    }

    #[test]
    fn rejects_ipv4_and_ipv6_link_local_addresses() {
        let listen_v4: SocketAddr = "0.0.0.0:4794".parse().unwrap();
        let listen_v6: SocketAddr = "[::]:4794".parse().unwrap();
        assert!(validate_family("169.254.10.20".parse().unwrap(), listen_v4, false).is_err());
        assert!(validate_family("fe80::10".parse().unwrap(), listen_v6, false).is_err());
    }
}
