use dtm_core::module_trait::Module;

// Phase 2: Simple modules
pub mod ad_tracking;
pub mod app_permissions;
pub mod certificates;
pub mod cookies;
pub mod dns;
pub mod email;
pub mod facebook;
pub mod fingerprint;
pub mod headers;
pub mod instagram;
pub mod location;
pub mod metadata;
pub mod search_noise;
pub mod secrets;
pub mod social;
pub mod social_noise;
pub mod ssh;
pub mod tiktok;
pub mod twitter;
pub mod webrtc;

// Phase 5: OAuth modules
pub mod reddit;
pub mod youtube;

// Phase 6: Agent modules (merged from agent/)
pub mod app_scanner;
pub mod dns_monitor;

/// All available modules, constructed as a Vec of boxed trait objects.
pub fn all_modules() -> Vec<Box<dyn Module>> {
    let mut modules: Vec<Box<dyn Module>> = vec![
        Box::new(cookies::CookiesModule),
        Box::new(secrets::SecretsModule),
        Box::new(ssh::SshModule),
        Box::new(headers::HeadersModule),
        Box::new(dns::DnsModule),
        Box::new(instagram::InstagramModule),
        Box::new(tiktok::TikTokModule),
        Box::new(facebook::FacebookModule),
        Box::new(twitter::TwitterModule),
        Box::new(search_noise::SearchNoiseModule),
        Box::new(social_noise::SocialNoiseModule),
        Box::new(location::LocationModule),
        Box::new(app_permissions::AppPermissionsModule),
        Box::new(fingerprint::FingerprintModule),
        Box::new(email::EmailModule),
        Box::new(metadata::MetadataModule),
        Box::new(webrtc::WebrtcModule),
        Box::new(social::SocialModule),
        Box::new(ad_tracking::AdTrackingModule),
        Box::new(certificates::CertificatesModule),
        Box::new(reddit::RedditModule),
        Box::new(youtube::YoutubeModule),
        Box::new(app_scanner::AppScannerModule),
        Box::new(dns_monitor::DnsMonitorModule),
    ];

    // Only include modules available on this platform
    modules.retain(|m| m.is_available());
    modules
}

/// Look up a module by name.
pub fn get_module(name: &str) -> Option<Box<dyn Module>> {
    all_modules().into_iter().find(|m| m.name() == name)
}
