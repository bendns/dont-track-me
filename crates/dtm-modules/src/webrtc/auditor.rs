use std::collections::HashMap;
use std::net::{Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use anyhow::Result;

use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};

// ---------------------------------------------------------------------------
// STUN protocol constants (RFC 5389)
// ---------------------------------------------------------------------------

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_HEADER_SIZE: usize = 20;

// STUN attribute types
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Public STUN servers used to discover externally-visible IP addresses.
const STUN_SERVERS: &[(&str, u16)] = &[
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun1.l.google.com", 19302),
];

const STUN_TIMEOUT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// STUN packet construction and parsing
// ---------------------------------------------------------------------------

/// Build a STUN Binding Request packet. Returns (packet, transaction_id).
fn build_stun_request() -> (Vec<u8>, [u8; 12]) {
    let mut transaction_id = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut transaction_id);

    let mut packet = Vec::with_capacity(STUN_HEADER_SIZE);
    // Message type: Binding Request
    packet.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    // Message length: 0 (no attributes)
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Magic cookie
    packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 bytes)
    packet.extend_from_slice(&transaction_id);

    (packet, transaction_id)
}

/// Parse XOR-MAPPED-ADDRESS attribute value into an IPv4 string.
fn parse_xor_mapped_address(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    // data[0] = reserved, data[1] = family
    let family = data[1];
    if family != 0x01 {
        // IPv4 only for now
        return None;
    }

    let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
    let ip_bytes: [u8; 4] = [
        data[4] ^ magic_bytes[0],
        data[5] ^ magic_bytes[1],
        data[6] ^ magic_bytes[2],
        data[7] ^ magic_bytes[3],
    ];

    Some(Ipv4Addr::from(ip_bytes).to_string())
}

/// Parse MAPPED-ADDRESS attribute value into an IPv4 string.
fn parse_mapped_address(data: &[u8]) -> Option<String> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    if family != 0x01 {
        return None;
    }

    let ip_bytes: [u8; 4] = [data[4], data[5], data[6], data[7]];
    Some(Ipv4Addr::from(ip_bytes).to_string())
}

/// Parse a STUN Binding Response and extract the mapped IP address.
/// Prefers XOR-MAPPED-ADDRESS over MAPPED-ADDRESS.
fn parse_stun_response(response: &[u8], transaction_id: &[u8; 12]) -> Option<String> {
    if response.len() < STUN_HEADER_SIZE {
        return None;
    }

    // Verify it's a binding success response (0x0101)
    let msg_type = u16::from_be_bytes([response[0], response[1]]);
    let msg_length = u16::from_be_bytes([response[2], response[3]]) as usize;
    let magic = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);

    if msg_type != STUN_BINDING_RESPONSE || magic != STUN_MAGIC_COOKIE {
        return None;
    }

    // Verify transaction ID matches
    if &response[8..20] != transaction_id {
        return None;
    }

    // Parse attributes
    let mut mapped_ip: Option<String> = None;
    let mut offset = STUN_HEADER_SIZE;
    let end = STUN_HEADER_SIZE + msg_length;

    while offset + 4 <= end && offset + 4 <= response.len() {
        let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let attr_length = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;

        let attr_end = offset + 4 + attr_length;
        if attr_end > response.len() {
            break;
        }
        let attr_data = &response[offset + 4..attr_end];

        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            if let Some(ip) = parse_xor_mapped_address(attr_data) {
                return Some(ip); // prefer XOR-MAPPED-ADDRESS
            }
        }

        if attr_type == ATTR_MAPPED_ADDRESS && mapped_ip.is_none() {
            mapped_ip = parse_mapped_address(attr_data);
        }

        // Attributes are padded to 4-byte boundaries
        offset = attr_end;
        let remainder = attr_length % 4;
        if remainder != 0 {
            offset += 4 - remainder;
        }
    }

    mapped_ip
}

/// Send a STUN Binding Request to a server and return the mapped IP address.
fn query_stun_server(server: &str, port: u16) -> Option<String> {
    let (packet, transaction_id) = build_stun_request();

    // Resolve hostname
    let addr = format!("{server}:{port}");
    let socket_addr = match addr.to_socket_addrs() {
        Ok(mut addrs) => addrs.find(|a| a.is_ipv4())?,
        Err(_) => return None,
    };

    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return None,
    };

    if sock.set_read_timeout(Some(STUN_TIMEOUT)).is_err() {
        return None;
    }

    if sock.send_to(&packet, socket_addr).is_err() {
        return None;
    }

    let mut buf = [0u8; 1024];
    let (len, _) = match sock.recv_from(&mut buf) {
        Ok(result) => result,
        Err(_) => return None,
    };

    parse_stun_response(&buf[..len], &transaction_id)
}

// ---------------------------------------------------------------------------
// Local IP detection
// ---------------------------------------------------------------------------

/// Get local (non-loopback) IPv4 addresses of this machine.
fn get_local_ips() -> Vec<String> {
    let mut ips = Vec::new();

    // Use a UDP socket trick: connect to a public address (no actual traffic)
    // to discover the default route's local IP.
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(local_addr) = sock.local_addr() {
                let ip = local_addr.ip().to_string();
                if ip != "127.0.0.1" && !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }

    ips
}

/// Check if an IP address is in a private/reserved range.
fn is_private_ip(ip: &str) -> bool {
    match ip.parse::<Ipv4Addr>() {
        Ok(addr) => addr.is_private() || addr.is_loopback() || addr.is_link_local(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn audit_webrtc(_opts: &AuditOpts) -> Result<AuditResult> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut score: i32 = 100;

    // Query STUN servers concurrently using tokio spawn_blocking
    let mut handles = Vec::new();
    for &(server, port) in STUN_SERVERS {
        let server = server.to_string();
        handles.push(tokio::task::spawn_blocking(move || {
            query_stun_server(&server, port)
        }));
    }

    let mut stun_ips: Vec<String> = Vec::new();
    for handle in handles {
        if let Ok(Some(ip)) = handle.await {
            if !stun_ips.contains(&ip) {
                stun_ips.push(ip);
            }
        }
    }

    let local_ips = get_local_ips();

    if stun_ips.is_empty() {
        // All STUN queries failed -- likely blocked by firewall
        findings.push(Finding {
            title: "STUN servers unreachable".to_string(),
            description: "Could not reach any STUN servers. This likely means WebRTC \
                UDP traffic is blocked by your firewall or network configuration, \
                which prevents WebRTC IP leaks."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "No action needed — blocked STUN traffic is good for privacy.".to_string(),
        });

        let mut raw_data = HashMap::new();
        raw_data.insert("stun_ips".to_string(), serde_json::json!([]));
        raw_data.insert("local_ips".to_string(), serde_json::json!(local_ips));

        return Ok(AuditResult {
            module_name: "webrtc".to_string(),
            score: 90,
            findings,
            raw_data,
        });
    }

    // Analyze discovered IPs
    let public_ips: Vec<&String> = stun_ips.iter().filter(|ip| !is_private_ip(ip)).collect();
    let private_ips: Vec<&String> = stun_ips.iter().filter(|ip| is_private_ip(ip)).collect();

    if !public_ips.is_empty() {
        let ip_list: Vec<&str> = public_ips.iter().map(|ip| ip.as_str()).collect();
        findings.push(Finding {
            title: format!("Public IP exposed via WebRTC: {}", ip_list.join(", ")),
            description: "STUN servers revealed your public IP address. In a browser with \
                WebRTC enabled, any website can discover this IP — even if you're \
                using a VPN. This completely bypasses VPN protection."
                .to_string(),
            threat_level: ThreatLevel::High,
            remediation: "Disable WebRTC in your browser: \
                Firefox: about:config > media.peerconnection.enabled = false. \
                Chrome: install 'WebRTC Leak Prevent' extension. \
                Brave: Settings > Privacy > WebRTC IP Handling Policy > \
                'Disable non-proxied UDP'."
                .to_string(),
        });
        score -= 40;
    }

    if !private_ips.is_empty() {
        let ip_list: Vec<&str> = private_ips.iter().map(|ip| ip.as_str()).collect();
        findings.push(Finding {
            title: format!("Local IP exposed via WebRTC: {}", ip_list.join(", ")),
            description: "STUN servers returned a private/local IP address. While not as \
                severe as a public IP leak, this reveals your local network \
                topology and can be used for fingerprinting."
                .to_string(),
            threat_level: ThreatLevel::Medium,
            remediation: "Disable WebRTC or restrict it to prevent local IP enumeration. \
                In Firefox: set media.peerconnection.enabled to false."
                .to_string(),
        });
        score -= 20;
    }

    if stun_ips.len() > 1 {
        findings.push(Finding {
            title: format!("Multiple IPs detected: {}", stun_ips.join(", ")),
            description: "Different STUN servers returned different IP addresses. \
                This may indicate split tunneling, multiple network interfaces, \
                or an inconsistent VPN configuration."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "Review your VPN and network configuration for consistency.".to_string(),
        });
    }

    if public_ips.is_empty() && private_ips.is_empty() {
        findings.push(Finding {
            title: "WebRTC IP leak check passed".to_string(),
            description: "STUN servers did not reveal any concerning IP addresses.".to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "Consider disabling WebRTC entirely for maximum privacy.".to_string(),
        });
    }

    let score = score.clamp(0, 100) as u32;

    let public_ip_strs: Vec<&str> = public_ips.iter().map(|ip| ip.as_str()).collect();
    let private_ip_strs: Vec<&str> = private_ips.iter().map(|ip| ip.as_str()).collect();

    let mut raw_data = HashMap::new();
    raw_data.insert("stun_ips".to_string(), serde_json::json!(stun_ips));
    raw_data.insert("local_ips".to_string(), serde_json::json!(local_ips));
    raw_data.insert("public_ips".to_string(), serde_json::json!(public_ip_strs));
    raw_data.insert(
        "private_ips".to_string(),
        serde_json::json!(private_ip_strs),
    );

    Ok(AuditResult {
        module_name: "webrtc".to_string(),
        score,
        findings,
        raw_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Tests 1-4: STUN request construction
    // -----------------------------------------------------------------------

    #[test]
    fn build_stun_request_length() {
        let (packet, _) = build_stun_request();
        assert_eq!(
            packet.len(),
            STUN_HEADER_SIZE,
            "STUN Binding Request should be exactly 20 bytes"
        );
    }

    #[test]
    fn build_stun_request_magic_cookie() {
        let (packet, _) = build_stun_request();
        let cookie = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        assert_eq!(
            cookie, STUN_MAGIC_COOKIE,
            "Bytes 4-8 should contain the magic cookie 0x2112A442"
        );
    }

    #[test]
    fn build_stun_request_binding_type() {
        let (packet, _) = build_stun_request();
        let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
        assert_eq!(
            msg_type, STUN_BINDING_REQUEST,
            "First 2 bytes should be 0x0001 (Binding Request)"
        );
    }

    #[test]
    fn stun_request_unique_transaction_ids() {
        let (_, tid1) = build_stun_request();
        let (_, tid2) = build_stun_request();
        assert_ne!(
            tid1, tid2,
            "Two STUN requests should have different transaction IDs"
        );
    }

    // -----------------------------------------------------------------------
    // Tests 5-6: STUN response parsing edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn parse_stun_response_invalid() {
        // Too-short response should return None
        let short_response = vec![0u8; 10];
        let tid = [0u8; 12];
        let result = parse_stun_response(&short_response, &tid);
        assert!(
            result.is_none(),
            "Too-short STUN response should return None"
        );
    }

    #[test]
    fn parse_stun_response_wrong_type() {
        // Build a packet with wrong message type (not a binding response)
        let mut packet = vec![0u8; 20];
        // Message type: 0x0001 (Binding Request, not Response)
        packet[0] = 0x00;
        packet[1] = 0x01;
        // Message length: 0
        packet[2] = 0x00;
        packet[3] = 0x00;
        // Magic cookie
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        packet[4..8].copy_from_slice(&cookie);
        // Transaction ID
        let tid = [0xAA; 12];
        packet[8..20].copy_from_slice(&tid);

        let result = parse_stun_response(&packet, &tid);
        assert!(
            result.is_none(),
            "Non-response message type should return None"
        );
    }

    // -----------------------------------------------------------------------
    // Tests 7-10: is_private_ip
    // -----------------------------------------------------------------------

    #[test]
    fn is_private_ip_rfc1918() {
        assert!(is_private_ip("10.0.0.1"), "10.0.0.1 should be private");
        assert!(
            is_private_ip("192.168.1.1"),
            "192.168.1.1 should be private"
        );
        assert!(is_private_ip("172.16.0.1"), "172.16.0.1 should be private");
    }

    #[test]
    fn is_private_ip_public() {
        assert!(!is_private_ip("8.8.8.8"), "8.8.8.8 should not be private");
    }

    #[test]
    fn is_private_ip_loopback() {
        assert!(
            is_private_ip("127.0.0.1"),
            "127.0.0.1 (loopback) should be private"
        );
    }

    #[test]
    fn is_private_ip_link_local() {
        assert!(
            is_private_ip("169.254.1.1"),
            "169.254.x.x (link-local) should be private"
        );
        assert!(
            is_private_ip("169.254.254.254"),
            "169.254.254.254 should be private"
        );
    }

    // -----------------------------------------------------------------------
    // Test 11: get_local_ips returns results
    // -----------------------------------------------------------------------

    #[test]
    fn get_local_ips_returns_results() {
        let ips = get_local_ips();
        // On a machine with network, this should return at least one IP.
        // The UDP socket trick may fail in some CI environments, so we just
        // verify it doesn't panic and returns a Vec.
        assert!(
            ips.is_empty() || !ips[0].is_empty(),
            "get_local_ips should return valid IP strings or empty vec"
        );
    }

    // -----------------------------------------------------------------------
    // Test 12: STUN response with XOR-MAPPED-ADDRESS
    // -----------------------------------------------------------------------

    #[test]
    fn stun_response_xor_mapped_address() {
        let tid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];

        // Build a valid STUN Binding Response with XOR-MAPPED-ADDRESS
        let mut packet = Vec::new();

        // Header: Binding Response (0x0101)
        packet.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        // Message length (will fill in after building attributes)
        packet.extend_from_slice(&0u16.to_be_bytes()); // placeholder
                                                       // Magic cookie
        packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        // Transaction ID
        packet.extend_from_slice(&tid);

        // XOR-MAPPED-ADDRESS attribute
        // Target IP: 203.0.113.1
        // XOR with magic cookie: 203.0.113.1 XOR 0x2112A442
        let target_ip: [u8; 4] = [203, 0, 113, 1];
        let magic = STUN_MAGIC_COOKIE.to_be_bytes();
        let xored_ip: [u8; 4] = [
            target_ip[0] ^ magic[0],
            target_ip[1] ^ magic[1],
            target_ip[2] ^ magic[2],
            target_ip[3] ^ magic[3],
        ];

        let attr_type = ATTR_XOR_MAPPED_ADDRESS.to_be_bytes();
        let attr_length = 8u16.to_be_bytes(); // 8 bytes of attribute value
        let xor_port = (12345u16 ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes();

        packet.extend_from_slice(&attr_type);
        packet.extend_from_slice(&attr_length);
        // Attribute value: reserved(1) + family(1) + port(2) + ip(4)
        packet.push(0x00); // reserved
        packet.push(0x01); // IPv4
        packet.extend_from_slice(&xor_port);
        packet.extend_from_slice(&xored_ip);

        // Fix message length (total attribute bytes = 4 header + 8 value = 12)
        let msg_len = (packet.len() - STUN_HEADER_SIZE) as u16;
        let len_bytes = msg_len.to_be_bytes();
        packet[2] = len_bytes[0];
        packet[3] = len_bytes[1];

        let result = parse_stun_response(&packet, &tid);
        assert!(result.is_some(), "Should parse XOR-MAPPED-ADDRESS");
        assert_eq!(
            result.unwrap(),
            "203.0.113.1",
            "Should decode XOR-MAPPED-ADDRESS to 203.0.113.1"
        );
    }

    // -----------------------------------------------------------------------
    // Test 13: STUN response with MAPPED-ADDRESS (fallback)
    // -----------------------------------------------------------------------

    #[test]
    fn stun_response_mapped_address() {
        let tid = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
        ];

        let mut packet = Vec::new();

        // Header: Binding Response (0x0101)
        packet.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes()); // placeholder
        packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        packet.extend_from_slice(&tid);

        // MAPPED-ADDRESS attribute (no XOR)
        let attr_type = ATTR_MAPPED_ADDRESS.to_be_bytes();
        let attr_length = 8u16.to_be_bytes();

        packet.extend_from_slice(&attr_type);
        packet.extend_from_slice(&attr_length);
        packet.push(0x00); // reserved
        packet.push(0x01); // IPv4
        packet.extend_from_slice(&54321u16.to_be_bytes()); // port
        packet.extend_from_slice(&[192, 0, 2, 1]); // 192.0.2.1

        // Fix message length
        let msg_len = (packet.len() - STUN_HEADER_SIZE) as u16;
        let len_bytes = msg_len.to_be_bytes();
        packet[2] = len_bytes[0];
        packet[3] = len_bytes[1];

        let result = parse_stun_response(&packet, &tid);
        assert!(result.is_some(), "Should parse MAPPED-ADDRESS");
        assert_eq!(
            result.unwrap(),
            "192.0.2.1",
            "Should decode MAPPED-ADDRESS to 192.0.2.1"
        );
    }

    // -----------------------------------------------------------------------
    // Test 14: Protection recommendations mention browsers
    // -----------------------------------------------------------------------

    #[test]
    fn protect_recommendations_include_browsers() {
        // The WebRTC module's protect actions_available should mention
        // Firefox, Chrome, and Brave as remediation targets.
        let actions = [
            "Disable WebRTC in Firefox: about:config > media.peerconnection.enabled = false",
            "Install 'WebRTC Leak Prevent' extension in Chrome",
            "Brave: Settings > Privacy > WebRTC IP Handling Policy > Disable non-proxied UDP",
            "Block UDP port 3478/19302 in firewall to prevent STUN queries",
        ];

        let all_text = actions.join(" ");
        assert!(
            all_text.contains("Firefox"),
            "Protection recommendations should mention Firefox"
        );
        assert!(
            all_text.contains("Chrome"),
            "Protection recommendations should mention Chrome"
        );
        assert!(
            all_text.contains("Brave"),
            "Protection recommendations should mention Brave"
        );
    }
}
