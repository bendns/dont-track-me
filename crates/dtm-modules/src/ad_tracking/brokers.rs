use serde::Deserialize;

use dtm_core::data::load_country_data;

/// A data broker entry loaded from shared/data/ad_tracking/<country>.yaml.
#[derive(Debug, Clone, Deserialize)]
pub struct Broker {
    pub name: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub opt_out_url: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BrokersFile {
    brokers: Vec<Broker>,
}

/// Load broker data for a given country code.
///
/// Returns an empty list if the YAML file is missing or malformed.
pub fn load_brokers(country: &str) -> Vec<Broker> {
    load_country_data::<BrokersFile>("ad_tracking", country)
        .map(|f| f.brokers)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonexistent_country_returns_empty() {
        let brokers = load_brokers("nonexistent_country_xyz");
        assert!(
            brokers.is_empty(),
            "Expected empty broker list for nonexistent country, got {} entries",
            brokers.len()
        );
    }

    #[test]
    fn load_us_brokers_returns_entries() {
        let brokers = load_brokers("us");
        assert!(
            !brokers.is_empty(),
            "Expected US broker data to have entries"
        );
        // Verify the struct fields are populated.
        for broker in &brokers {
            assert!(!broker.name.is_empty(), "Broker name should not be empty");
        }
    }

    #[test]
    fn load_fr_brokers_returns_entries() {
        let brokers = load_brokers("fr");
        assert!(
            !brokers.is_empty(),
            "Expected FR broker data to have entries"
        );
    }

    #[test]
    fn broker_struct_fields_populated() {
        let brokers = load_brokers("us");
        if let Some(broker) = brokers.first() {
            // name is always required.
            assert!(!broker.name.is_empty());
            // category, url, opt_out_url are optional -- just verify they deserialize.
            // No panic means the serde defaults work correctly.
        }
    }
}
