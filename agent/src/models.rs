use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Result of scanning a single application bundle for tracking SDKs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppScanResult {
    pub app_name: String,
    pub bundle_id: Option<String>,
    pub app_path: String,
    pub tracking_sdks: Vec<TrackingSdk>,
    pub ats_exceptions: Vec<String>,
    pub binary_size: u64,
    pub scanned_at: DateTime<Utc>,
}

/// A tracking SDK detected in an application binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingSdk {
    pub name: String,
    pub category: String,
    pub matched_dylib: String,
}

/// A DNS query event captured from network traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    pub timestamp: DateTime<Utc>,
    pub domain: String,
    pub query_type: String,
    pub is_tracker: bool,
    pub tracker_category: Option<String>,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
}
