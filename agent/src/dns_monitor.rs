use std::collections::HashMap;
use std::process::Command;
use std::time::Instant;

use chrono::Utc;
use log::{debug, info, warn};
use pcap::Capture;
use rusqlite::Connection;

use crate::db::insert_dns_event;
use crate::models::DnsEvent;
use crate::tracker_domains::match_tracker_domain;

/// Cache TTL for process lookups (seconds).
const PROCESS_CACHE_TTL_SECS: u64 = 5;
/// Maximum cache entries before eviction.
const PROCESS_CACHE_MAX: usize = 256;

/// Cached process lookup result.
struct CachedProcess {
    name: Option<String>,
    pid: Option<u32>,
    fetched_at: Instant,
}

/// Start capturing DNS queries on the default network interface.
///
/// Requires root privileges or membership in the `bpf` group on macOS.
/// Captured tracker DNS queries are written to the database.
pub fn monitor_dns(
    conn: &Connection,
    interface: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let device = match interface {
        Some(iface) => iface.to_string(),
        None => find_default_interface()?,
    };

    info!("Starting DNS capture on interface: {device}");

    let mut cap = Capture::from_device(device.as_str())?
        .promisc(false)
        .snaplen(512) // DNS packets are small
        .timeout(1000) // 1 second read timeout
        .open()?;

    // BPF filter: only capture DNS traffic (UDP port 53)
    cap.filter("udp port 53", true)?;

    info!("DNS monitor active. Capturing queries...");

    let mut total_queries: u64 = 0;
    let mut tracker_queries: u64 = 0;
    let mut process_cache: HashMap<u16, CachedProcess> = HashMap::new();
    let mut consecutive_errors: u32 = 0;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                consecutive_errors = 0;
                if let Some(event) = parse_dns_packet(packet.data, &mut process_cache) {
                    total_queries += 1;

                    if event.is_tracker {
                        tracker_queries += 1;
                        info!(
                            "TRACKER DNS: {} -> {} ({})",
                            event.process_name.as_deref().unwrap_or("unknown"),
                            event.domain,
                            event.tracker_category.as_deref().unwrap_or("unknown")
                        );
                    } else {
                        debug!("DNS query: {}", event.domain);
                    }

                    if let Err(e) = insert_dns_event(conn, &event) {
                        warn!("Failed to insert DNS event: {e}");
                    }

                    if total_queries % 100 == 0 {
                        info!("Captured {total_queries} DNS queries ({tracker_queries} tracker)");
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Normal — pcap read timeout with no packets, continue
                continue;
            }
            Err(e) => {
                consecutive_errors += 1;
                warn!("pcap error: {e}");
                if consecutive_errors >= 10 {
                    return Err(format!(
                        "Too many consecutive pcap errors ({consecutive_errors}): {e}"
                    )
                    .into());
                }
            }
        }
    }
}

/// Find the default network interface on macOS.
fn find_default_interface() -> Result<String, Box<dyn std::error::Error>> {
    // Use `route get default` to find the default interface on macOS
    let output = Command::new("route").args(["get", "default"]).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(iface) = line.strip_prefix("interface:") {
            return Ok(iface.trim().to_string());
        }
    }

    // Fallback to en0 (most common macOS default)
    warn!("Could not detect default interface, falling back to en0");
    Ok("en0".to_string())
}

/// Parse a raw Ethernet frame containing a DNS query packet.
///
/// Returns a DnsEvent if the packet contains a DNS query (not a response).
fn parse_dns_packet(
    data: &[u8],
    process_cache: &mut HashMap<u16, CachedProcess>,
) -> Option<DnsEvent> {
    // Ethernet header is 14 bytes
    if data.len() < 14 {
        return None;
    }

    let eth_type = u16::from_be_bytes([data[12], data[13]]);

    let ip_header_start = match eth_type {
        0x0800 => 14, // IPv4
        0x86DD => 14, // IPv6
        _ => return None,
    };

    let (udp_start, src_port_offset) = if eth_type == 0x0800 {
        // IPv4: variable header length
        if data.len() < ip_header_start + 20 {
            return None;
        }
        let ihl = (data[ip_header_start] & 0x0F) as usize * 4;
        let protocol = data[ip_header_start + 9];
        if protocol != 17 {
            // Not UDP
            return None;
        }
        (ip_header_start + ihl, ip_header_start + ihl)
    } else {
        // IPv6: fixed 40-byte header, check next header
        if data.len() < ip_header_start + 40 {
            return None;
        }
        let next_header = data[ip_header_start + 6];
        if next_header != 17 {
            // Not UDP (simplified — doesn't handle extension headers)
            return None;
        }
        (ip_header_start + 40, ip_header_start + 40)
    };

    // UDP header is 8 bytes
    if data.len() < udp_start + 8 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[src_port_offset], data[src_port_offset + 1]]);
    let dst_port = u16::from_be_bytes([data[src_port_offset + 2], data[src_port_offset + 3]]);

    // We only want DNS queries (destination port 53)
    if dst_port != 53 {
        return None;
    }

    let dns_start = udp_start + 8;
    if data.len() < dns_start + 12 {
        return None;
    }

    // DNS header fields
    let flags = u16::from_be_bytes([data[dns_start + 2], data[dns_start + 3]]);
    let qr = (flags >> 15) & 1;
    if qr != 0 {
        // This is a response, not a query
        return None;
    }

    let qdcount = u16::from_be_bytes([data[dns_start + 4], data[dns_start + 5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse the query name
    let (domain, query_end) = parse_dns_name(data, dns_start + 12)?;

    // Parse query type
    let query_type = if data.len() >= query_end + 2 {
        let qtype = u16::from_be_bytes([data[query_end], data[query_end + 1]]);
        match qtype {
            1 => "A",
            28 => "AAAA",
            5 => "CNAME",
            15 => "MX",
            2 => "NS",
            12 => "PTR",
            16 => "TXT",
            6 => "SOA",
            33 => "SRV",
            65 => "HTTPS",
            _ => "OTHER",
        }
        .to_string()
    } else {
        "UNKNOWN".to_string()
    };

    // Check if domain is a tracker
    let tracker_category = match_tracker_domain(&domain);
    let is_tracker = tracker_category.is_some();

    // Try to identify the process (cached, best-effort)
    let (process_name, process_pid) = lookup_process_cached(src_port, process_cache);

    Some(DnsEvent {
        timestamp: Utc::now(),
        domain,
        query_type,
        is_tracker,
        tracker_category: tracker_category.map(String::from),
        process_name,
        process_pid,
    })
}

/// Parse a DNS name from a packet at the given offset.
/// Returns (domain_string, offset_after_name).
fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut end_offset = 0;
    let max_iterations = 128; // Prevent infinite loops from malformed packets
    let mut iterations = 0;

    loop {
        iterations += 1;
        if iterations > max_iterations || offset >= data.len() {
            return None;
        }

        let len = data[offset] as usize;

        if len == 0 {
            if !jumped {
                end_offset = offset + 1;
            }
            break;
        }

        // Check for DNS name compression (pointer)
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            if !jumped {
                end_offset = offset + 2;
            }
            let pointer = ((len & 0x3F) << 8) | data[offset + 1] as usize;
            offset = pointer;
            jumped = true;
            continue;
        }

        offset += 1;
        if offset + len > data.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
        parts.push(label);
        offset += len;
    }

    if parts.is_empty() {
        return None;
    }

    let domain = parts.join(".");
    Some((domain, end_offset))
}

/// Look up the process for a source port, using a time-limited cache to avoid
/// spawning `lsof` on every packet.
fn lookup_process_cached(
    port: u16,
    cache: &mut HashMap<u16, CachedProcess>,
) -> (Option<String>, Option<u32>) {
    let now = Instant::now();

    // Return cached result if still fresh
    if let Some(entry) = cache.get(&port) {
        if now.duration_since(entry.fetched_at).as_secs() < PROCESS_CACHE_TTL_SECS {
            return (entry.name.clone(), entry.pid);
        }
    }

    // Evict stale entries when cache is too large
    if cache.len() >= PROCESS_CACHE_MAX {
        cache.retain(|_, v| now.duration_since(v.fetched_at).as_secs() < PROCESS_CACHE_TTL_SECS);
    }

    let (name, pid) = lookup_process_by_port(port);
    cache.insert(
        port,
        CachedProcess {
            name: name.clone(),
            pid,
            fetched_at: now,
        },
    );
    (name, pid)
}

/// Try to find the process that owns a given UDP source port.
/// Uses `lsof` on macOS (best-effort, may fail without root).
fn lookup_process_by_port(port: u16) -> (Option<String>, Option<u32>) {
    let output = match Command::new("lsof")
        .args(["-i", &format!("UDP:{port}"), "-n", "-P", "-F", "pcn"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return (None, None),
    };

    if !output.status.success() {
        return (None, None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut pid: Option<u32> = None;
    let mut name: Option<String> = None;

    for line in stdout.lines() {
        if let Some(p) = line.strip_prefix('p') {
            pid = p.parse().ok();
        } else if let Some(c) = line.strip_prefix('c') {
            name = Some(c.to_string());
        }
    }

    (name, pid)
}

/// Print a live-updating header for DNS monitoring.
pub fn print_monitor_header() {
    println!("\n=== DNS Tracker Monitor ===\n");
    println!("Capturing DNS queries and matching against known tracker domains.");
    println!("Press Ctrl+C to stop.\n");
    println!(
        "{:<24} {:<6} {:<40} {:<16} {}",
        "TIMESTAMP", "TYPE", "DOMAIN", "CATEGORY", "PROCESS"
    );
    println!("{}", "-".repeat(100));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet for testing.
    fn build_dns_query_packet(domain: &str) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0u8; 12]); // dst + src MAC
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes, minimal)
        pkt.push(0x45); // Version 4, IHL 5
        pkt.push(0x00); // DSCP
        pkt.extend_from_slice(&[0x00, 0x00]); // Total length (placeholder)
        pkt.extend_from_slice(&[0x00, 0x00]); // ID
        pkt.extend_from_slice(&[0x00, 0x00]); // Flags + fragment
        pkt.push(64); // TTL
        pkt.push(17); // Protocol: UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // Header checksum
        pkt.extend_from_slice(&[10, 0, 0, 1]); // Src IP
        pkt.extend_from_slice(&[8, 8, 8, 8]); // Dst IP

        // UDP header (8 bytes)
        pkt.extend_from_slice(&[0xC0, 0x00]); // Src port: 49152
        pkt.extend_from_slice(&[0x00, 0x35]); // Dst port: 53
        pkt.extend_from_slice(&[0x00, 0x00]); // Length (placeholder)
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum

        // DNS header (12 bytes)
        pkt.extend_from_slice(&[0x00, 0x01]); // Transaction ID
        pkt.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
        pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

        // DNS query name
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00); // Root label

        // Query type (A = 1) and class (IN = 1)
        pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE: A
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN

        pkt
    }

    #[test]
    fn test_parse_dns_query_tracker() {
        let mut cache = HashMap::new();
        let pkt = build_dns_query_packet("ads.doubleclick.net");
        let event = parse_dns_packet(&pkt, &mut cache).unwrap();
        assert_eq!(event.domain, "ads.doubleclick.net");
        assert_eq!(event.query_type, "A");
        assert!(event.is_tracker);
        assert_eq!(event.tracker_category.as_deref(), Some("advertising"));
    }

    #[test]
    fn test_parse_dns_query_non_tracker() {
        let mut cache = HashMap::new();
        let pkt = build_dns_query_packet("www.rust-lang.org");
        let event = parse_dns_packet(&pkt, &mut cache).unwrap();
        assert_eq!(event.domain, "www.rust-lang.org");
        assert!(!event.is_tracker);
        assert!(event.tracker_category.is_none());
    }

    #[test]
    fn test_parse_dns_query_facebook() {
        let mut cache = HashMap::new();
        let pkt = build_dns_query_packet("pixel.facebook.com");
        let event = parse_dns_packet(&pkt, &mut cache).unwrap();
        assert_eq!(event.domain, "pixel.facebook.com");
        assert!(event.is_tracker);
        assert_eq!(event.tracker_category.as_deref(), Some("social"));
    }

    #[test]
    fn test_parse_too_short() {
        let mut cache = HashMap::new();
        let pkt = vec![0u8; 10];
        assert!(parse_dns_packet(&pkt, &mut cache).is_none());
    }

    #[test]
    fn test_parse_dns_response_ignored() {
        let mut cache = HashMap::new();
        let mut pkt = build_dns_query_packet("example.com");
        // Flip QR bit to make it a response
        let dns_start = 14 + 20 + 8; // eth + ip + udp
        pkt[dns_start + 2] |= 0x80; // Set QR bit
        assert!(parse_dns_packet(&pkt, &mut cache).is_none());
    }

    #[test]
    fn test_parse_dns_name_simple() {
        // "www.example.com" encoded
        let data: Vec<u8> = vec![
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ];
        let (name, end) = parse_dns_name(&data, 0).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(end, data.len());
    }
}
