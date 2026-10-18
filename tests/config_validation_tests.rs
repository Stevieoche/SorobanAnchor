#![cfg(feature = "std")]

use std::{fs, path::PathBuf};

use anchorkit::{load_runtime_config_file, parse_runtime_config_str, ConfigFormat};
use jsonschema::JSONSchema;
use serde_json::Value;

const SCHEMA: &str = "config_schema.json";
const CONFIG_DIR: &str = "configs";

fn config_paths() -> Vec<PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(CONFIG_DIR)
        .expect("configs directory should exist")
        .map(|entry| entry.expect("config entry should be readable").path())
        .filter(|path| {
            path.is_file()
                && matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("json" | "toml")
                )
        })
        .collect();
    paths.sort();
    paths
}

fn config_to_json_value(path: &PathBuf) -> Value {
    let input = fs::read_to_string(path).expect("config should be readable");
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => serde_json::from_str(&input).expect("JSON config should parse"),
        Some("toml") => {
            let value: toml::Value = toml::from_str(&input).expect("TOML config should parse");
            serde_json::to_value(value).expect("TOML config should convert to JSON value")
        }
        _ => panic!("unsupported config extension: {}", path.display()),
    }
}

fn compiled_schema() -> JSONSchema {
    let schema_text = fs::read_to_string(SCHEMA).expect("schema should be readable");
    let schema_json: Value = serde_json::from_str(&schema_text).expect("schema should be JSON");
    JSONSchema::compile(&schema_json).expect("schema should compile as JSON Schema")
}

#[test]
fn config_schema_is_valid_json_schema() {
    let _ = compiled_schema();
}

#[test]
fn all_example_configs_validate_against_schema() {
    let schema = compiled_schema();
    let paths = config_paths();
    assert!(!paths.is_empty(), "expected at least one example config");

    for path in paths {
        let value = config_to_json_value(&path);
        let validation = schema.validate(&value);
        let errors = match validation {
            Ok(()) => Vec::new(),
            Err(errors) => errors.map(|err| err.to_string()).collect(),
        };
        assert!(
            errors.is_empty(),
            "{} failed schema validation:\n{}",
            path.display(),
            errors.join("\n")
        );
    }
}

#[test]
fn all_example_configs_load_with_runtime_parser() {
    let paths = config_paths();
    assert!(!paths.is_empty(), "expected at least one example config");

    for path in paths {
        load_runtime_config_file(&path)
            .unwrap_or_else(|err| panic!("{} failed runtime parsing: {err}", path.display()));
    }
}

#[test]
fn runtime_parser_rejects_unknown_top_level_section() {
    let bad = r#"{
  "contract": { "name": "bad-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [{
      "name": "kyc-issuer",
      "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
      "role": "kyc-issuer",
      "enabled": true
    }]
  },
  "unsupported": { "value": true }
}"#;

    let result = parse_runtime_config_str(bad, ConfigFormat::Json);
    assert!(result.is_err(), "unsupported top-level section should be rejected");
}

#[test]
fn runtime_parser_rejects_malformed_nested_shape() {
    let bad = r#"{
  "contract": { "name": "bad-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [{
      "name": "kyc-issuer",
      "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
      "role": "kyc-issuer",
      "enabled": true,
      "mystery_flag": true
    }]
  }
}"#;

    let result = parse_runtime_config_str(bad, ConfigFormat::Json);
    assert!(result.is_err(), "unknown nested attestor field should be rejected");
}

#[test]
fn runtime_parser_rejects_unknown_attestor_references() {
    let bad = r#"{
  "contract": { "name": "bad-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [{
      "name": "kyc-issuer",
      "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
      "role": "kyc-issuer",
      "enabled": true
    }]
  },
  "operations": {
    "templates": [{
      "id": "missing-attestor",
      "name": "Missing Attestor",
      "attestor": "not-registered",
      "operation_type": "kyc",
      "required_fields": ["user_id"],
      "replay_protection": "enabled"
    }]
  }
}"#;

    let result = parse_runtime_config_str(bad, ConfigFormat::Json);
    assert!(result.is_err(), "unknown operation attestor should be rejected");
}

// ── Whitespace-name trimming ──────────────────────────────────────────────────

#[test]
fn whitespace_only_contract_name_is_rejected() {
    let bad = r#"{
  "contract": { "name": "   ", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [{
      "name": "kyc-issuer",
      "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
      "role": "kyc-issuer",
      "enabled": true
    }]
  }
}"#;
    // The schema enforces pattern ^[a-z0-9-]+$ so whitespace is also caught
    // at the schema layer; the semantic layer provides the trim-aware message.
    let result = parse_runtime_config_str(bad, ConfigFormat::Json);
    assert!(result.is_err(), "whitespace-only contract name should be rejected");
}

#[test]
fn ordinary_contract_name_is_accepted() {
    let good = r#"{
  "contract": { "name": "my-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [{
      "name": "kyc-issuer",
      "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
      "role": "kyc-issuer",
      "enabled": true
    }]
  }
}"#;
    let result = parse_runtime_config_str(good, ConfigFormat::Json);
    assert!(result.is_ok(), "ordinary name should be accepted: {:?}", result);
}

// ── Duplicate attestor names ──────────────────────────────────────────────────

#[test]
fn duplicate_attestor_name_is_rejected() {
    let bad = r#"{
  "contract": { "name": "my-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [
      {
        "name": "kyc-issuer",
        "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
        "role": "kyc-issuer",
        "enabled": true
      },
      {
        "name": "kyc-issuer",
        "address": "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGBM3NMKL3YEI6CGMFA8QQ",
        "role": "transfer-verifier",
        "enabled": true
      }
    ]
  }
}"#;
    let result = parse_runtime_config_str(bad, ConfigFormat::Json);
    assert!(result.is_err(), "duplicate attestor name should be rejected");
    let err = result.unwrap_err();
    assert!(
        err.contains("kyc-issuer"),
        "error should identify the conflicting name, got: {err}"
    );
}

#[test]
fn unique_attestor_names_are_accepted() {
    let good = r#"{
  "contract": { "name": "my-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [
      {
        "name": "kyc-issuer",
        "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
        "role": "kyc-issuer",
        "enabled": true
      },
      {
        "name": "transfer-verifier",
        "address": "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGBM3NMKL3YEI6CGMFA8QQ",
        "role": "transfer-verifier",
        "enabled": true
      }
    ]
  }
}"#;
    let result = parse_runtime_config_str(good, ConfigFormat::Json);
    assert!(result.is_ok(), "unique attestor names should be accepted: {:?}", result);
}

// ── Schema validation (validate_against_schema) ───────────────────────────────

#[test]
fn schema_rejects_wrong_type_for_contract_field() {
    // "version" must be a string, not an integer
    let bad = r#"{
  "contract": { "name": "my-anchor", "version": 1, "network": "stellar-testnet" },
  "attestors": {
    "registry": [{
      "name": "kyc-issuer",
      "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
      "role": "kyc-issuer",
      "enabled": true
    }]
  }
}"#;
    let result = parse_runtime_config_str(bad, ConfigFormat::Json);
    assert!(result.is_err(), "wrong type for version should be rejected by schema");
}

#[test]
fn schema_rejects_missing_required_property() {
    // "network" is required under contract
    let bad = r#"{
  "contract": { "name": "my-anchor", "version": "1.0.0" },
  "attestors": {
    "registry": [{
      "name": "kyc-issuer",
      "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
      "role": "kyc-issuer",
      "enabled": true
    }]
  }
}"#;
    let result = parse_runtime_config_str(bad, ConfigFormat::Json);
    assert!(result.is_err(), "missing required 'network' field should be rejected by schema");
}

#[test]
fn schema_rejects_unknown_top_level_property() {
    let bad = r#"{
  "contract": { "name": "my-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [{
      "name": "kyc-issuer",
      "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
      "role": "kyc-issuer",
      "enabled": true
    }]
  },
  "unknown_field": "should_fail"
}"#;
    let result = parse_runtime_config_str(bad, ConfigFormat::Json);
    assert!(result.is_err(), "unknown top-level field should be rejected by schema");
}

#[test]
fn valid_config_still_parses_through_schema_path() {
    let good = r#"{
  "contract": { "name": "my-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [{
      "name": "kyc-issuer",
      "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
      "role": "kyc-issuer",
      "enabled": true
    }]
  }
}"#;
    let result = parse_runtime_config_str(good, ConfigFormat::Json);
    assert!(result.is_ok(), "valid config should pass schema validation: {:?}", result);
}


// ── Schema boundary: session_timeout_seconds maximum (86400) ─────────────────
//
// The schema pins operator-facing limits on session settings, registry size,
// and audit retention. This pair exercises one configured maximum
// (sessions.session_timeout_seconds) at the allowed value and one unit beyond
// it so the boundary stays intentional and drift between validation and
// documentation surfaces here. Both cases run through the production
// parse_runtime_config_str path (schema validation + typed deserialization +
// semantic validation). No schema limits are changed by this test.

#[test]
fn session_timeout_at_maximum_is_accepted() {
    let json = r#"{
  "contract": { "name": "my-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [{
      "name": "kyc-issuer",
      "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
      "role": "kyc-issuer",
      "enabled": true
    }]
  },
  "sessions": { "session_timeout_seconds": 86400 }
}"#;
    let result = parse_runtime_config_str(json, ConfigFormat::Json);
    assert!(
        result.is_ok(),
        "session_timeout_seconds at the configured maximum (86400) should be accepted: {:?}",
        result
    );
}

#[test]
fn session_timeout_one_over_maximum_is_rejected() {
    let json = r#"{
  "contract": { "name": "my-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [{
      "name": "kyc-issuer",
      "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
      "role": "kyc-issuer",
      "enabled": true
    }]
  },
  "sessions": { "session_timeout_seconds": 86401 }
}"#;
    let result = parse_runtime_config_str(json, ConfigFormat::Json);
    assert!(
        result.is_err(),
        "session_timeout_seconds one unit above the maximum (86401) should be rejected"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("schema validation failed"),
        "over-limit value should be rejected by the schema validation path, got: {err}"
    );
    assert!(
        err.contains("session_timeout_seconds"),
        "error should reference the bounded field, got: {err}"
    );
}

// ── Required-property regression: attestors.registry ──────────────────────────
//
// The schema marks `attestors.registry` as required (minItems 1). Removing it
// must fail through the production validator with an intelligible error that
// references the missing property or its containing path. This complements the
// existing schema_rejects_missing_required_property test (which covers
// contract.network) by protecting the registry key, a nested required property.

#[test]
fn missing_attestors_registry_is_rejected() {
    let bad = r#"{
  "contract": { "name": "my-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {}
}"#;
    let result = parse_runtime_config_str(bad, ConfigFormat::Json);
    assert!(result.is_err(), "missing attestors.registry should be rejected");
    let err = result.unwrap_err();
    assert!(
        err.contains("attestors") || err.contains("registry"),
        "error should reference the attestors/registry path, got: {err}"
    );
}

// ── Duplicate attestor address: current behavior regression ──────────────────
//
// The semantic validator rejects duplicate attestor *names* but does NOT reject
// duplicate attestor *addresses*. Two registry entries sharing the same on-chain
// address (with distinct names and roles) currently parse successfully.
//
// This is a known limitation, not an enforced policy. This test pins the
// current behavior so any future change (e.g., introducing a duplicate-address
// check) must intentionally update this regression rather than silently shifting
// validation semantics. Per the issue scope, no new registry policy is added
// here; the three example configuration pairs continue to validate unchanged.

#[test]
fn duplicate_attestor_address_is_currently_accepted() {
    // Two attestors share the same address but have unique names and roles.
    let json = r#"{
  "contract": { "name": "my-anchor", "version": "1.0.0", "network": "stellar-testnet" },
  "attestors": {
    "registry": [
      {
        "name": "kyc-issuer",
        "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
        "role": "kyc-issuer",
        "enabled": true
      },
      {
        "name": "transfer-verifier",
        "address": "GBBD6A7KNZF5WNWQEPZP5DYJD2AYUTLXRB6VXJ4RCX4RTNPPQVNF3GQ",
        "role": "transfer-verifier",
        "enabled": true
      }
    ]
  }
}"#;
    let result = parse_runtime_config_str(json, ConfigFormat::Json);
    assert!(
        result.is_ok(),
        "duplicate attestor addresses are currently accepted (documented limitation): {:?}",
        result
    );
}

// ── JSON/TOML example parity ──────────────────────────────────────────────────
//
// The repository ships JSON and TOML versions of each deployment example. This
// guard ensures each pair agrees on the required deployment fields (contract
// identity and network) and the attestor registry entries (the core
// configuration that downstream validation depends on). Optional display fields
// such as admin_address, description, endpoint, and contact_email are permitted
// to differ between formats and are intentionally not compared. Both files are
// loaded through the production load_runtime_config_file path; no new runtime
// dependency is introduced.

#[test]
fn json_toml_config_pairs_agree_on_required_fields() {
    let pairs: &[(&str, &str, &str)] = &[
        ("fiat-on-off-ramp", "configs/fiat-on-off-ramp.json", "configs/fiat-on-off-ramp.toml"),
        ("remittance-anchor", "configs/remittance-anchor.json", "configs/remittance-anchor.toml"),
        ("stablecoin-issuer", "configs/stablecoin-issuer.json", "configs/stablecoin-issuer.toml"),
    ];

    for (label, json_path, toml_path) in pairs {
        let json_cfg = load_runtime_config_file(json_path)
            .unwrap_or_else(|e| panic!("{label}: JSON config failed to load: {e}"));
        let toml_cfg = load_runtime_config_file(toml_path)
            .unwrap_or_else(|e| panic!("{label}: TOML config failed to load: {e}"));

        // Required contract deployment fields.
        assert_eq!(json_cfg.contract.name, toml_cfg.contract.name, "{label}: contract.name mismatch");
        assert_eq!(json_cfg.contract.version, toml_cfg.contract.version, "{label}: contract.version mismatch");
        assert_eq!(json_cfg.contract.network, toml_cfg.contract.network, "{label}: contract.network mismatch");

        // Attestor registry: same count, and each entry agrees on its required
        // fields (name, address, role, enabled).
        let json_registry = &json_cfg.attestors.registry;
        let toml_registry = &toml_cfg.attestors.registry;
        assert_eq!(
            json_registry.len(),
            toml_registry.len(),
            "{label}: attestors.registry length mismatch (JSON={} TOML={})",
            json_registry.len(),
            toml_registry.len()
        );
        for (index, (j, t)) in json_registry.iter().zip(toml_registry.iter()).enumerate() {
            assert_eq!(j.name, t.name, "{label}: registry[{index}].name mismatch");
            assert_eq!(j.address, t.address, "{label}: registry[{index}].address mismatch");
            assert_eq!(j.role, t.role, "{label}: registry[{index}].role mismatch");
            assert_eq!(j.enabled, t.enabled, "{label}: registry[{index}].enabled mismatch");
        }
    }
}
