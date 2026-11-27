use std::sync::LazyLock;

use crate::context::{BuildArch, OsFamily};
use crate::packs::CATALOG;
use crate::{ContextBuilder, Pack, RunContext};
use serde_json::{Value, json};

static SCHEMA: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../tests/fixtures/box.schema.json")).unwrap()
});

/// The service schema this crate's payloads are checked against.
pub(crate) fn schema() -> &'static Value {
    &SCHEMA
}

/// The sorted values the schema allows at `pointer`, an `enum` or a `oneOf` with one.
pub(crate) fn schema_enum(pointer: &str) -> Vec<String> {
    let node = schema()
        .pointer(pointer)
        .unwrap_or_else(|| panic!("{pointer}"));
    let values = node.get("enum").or_else(|| {
        node["oneOf"]
            .as_array()?
            .iter()
            .find_map(|branch| branch.get("enum"))
    });
    let mut values: Vec<String> = values
        .unwrap_or_else(|| panic!("{pointer} has no enum"))
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    values.sort_unstable();
    values
}

/// The sorted JSON strings that `values` serialize to.
pub(crate) fn serialized<T: serde::Serialize>(values: &[T]) -> Vec<String> {
    let mut texts: Vec<String> = values
        .iter()
        .map(|value| {
            serde_json::to_value(value)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    texts.sort_unstable();
    texts
}

fn builder() -> ContextBuilder {
    ContextBuilder::new("1.2.3").unwrap()
}

fn snapshot(builder: ContextBuilder) -> Value {
    serde_json::to_value(builder.finish()).unwrap()
}

const BASE: &[u8] = include_bytes!("../../../../resources/packs/base/pack.toml");
const CLAUDE: &[u8] = include_bytes!("../../../../resources/packs/claude/pack.toml");

fn pack<'a>(id: Option<&'a str>, bytes: &'a [u8], bundled_location: Option<bool>) -> Pack<'a> {
    Pack {
        id,
        bytes,
        grammar: None,
        bundled_location,
    }
}

fn validator() -> jsonschema::Validator {
    jsonschema::draft4::new(&schema()["definitions"]["run_context"]).unwrap()
}

#[test]
fn context_contains_normalized_metadata_and_explicit_unknowns() {
    for (os, family) in [
        ("macos", "macos"),
        ("linux", "linux"),
        ("windows", "windows"),
        ("freebsd", "other"),
        ("", "other"),
    ] {
        for (arch, target) in [
            ("aarch64", "aarch64"),
            ("x86_64", "x86_64"),
            ("arm", "other"),
        ] {
            let context = RunContext::new("9.8.7", os, Some("14.5".to_owned()), arch).unwrap();
            assert_eq!(context, context.clone());
            let value = serde_json::to_value(context).unwrap();
            assert_eq!(
                value,
                json!({
                    "box_version": "9.8.7",
                    "os_family": family,
                    "os_version": "14.5",
                    "build_arch": target,
                    "builtin_packs": null,
                    "mcp_configured": null,
                    "has_custom_packs": null,
                    "profile_policy_present": null,
                    "profile_hash": null
                })
            );
            assert!(validator().is_valid(&value));
        }
    }
}

#[test]
fn version_is_normalized_and_bounded_by_the_schema() {
    for valid in ["0.0.0", "1.2.3", "9999.9999.9999"] {
        assert!(ContextBuilder::new(valid).is_ok());
    }
    for invalid in [
        "",
        "1.2",
        "1.2.3.4",
        "01.2.3",
        "1.2.3-rc.1",
        "1.2.3+build",
        "1.10000.3",
        "10000.2.3",
        "1.2.10000",
        "1.2.-3",
        "1.2.+3",
        "1.2.3\n",
    ] {
        assert!(ContextBuilder::new(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn profile_hashes_saved_bytes_and_retains_no_source() {
    let mut context = builder();
    let mut bytes = b"abc".to_vec();
    context.profile(&bytes);
    bytes.clear();
    let value = snapshot(context);
    assert_eq!(
        value["profile_hash"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(!value.to_string().contains("abc"));

    let mut context = builder();
    context.profile(b"abc\n");
    assert_eq!(
        snapshot(context)["profile_hash"],
        "edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb"
    );
}

#[test]
fn policy_observation_reads_the_declared_list_and_preserves_unknowns() {
    for (bytes, expected) in [
        (b"".as_slice(), Some(false)),
        (b"policies = []", Some(false)),
        (b"policies = ['rules.dw']", Some(true)),
        (b"policies = ['rules.dw', 'extra.dw']", Some(true)),
        (b"policies = ['missing.dw']", Some(true)),
        (b"policies = 'rules.dw'", None),
        (b"policies = [false]", None),
        (b"policies = ['']", None),
        (b"policies = ['${{ root }}/rules.dw']", None),
        (b"[", None),
        (b"\xff", None),
    ] {
        let mut context = builder();
        context.profile(bytes);
        assert_eq!(
            snapshot(context)["profile_policy_present"],
            json!(expected),
            "{bytes:?}"
        );
    }
}

#[test]
fn pack_graph_is_sorted_unique_and_excludes_custom_names() {
    let mut context = builder();
    context.packs([
        pack(Some("claude"), CLAUDE, Some(true)),
        pack(None, b"secret profile text", Some(false)),
        pack(Some("private-customer"), b"private", Some(true)),
        pack(Some("base"), BASE, Some(true)),
        pack(Some("claude"), CLAUDE, Some(true)),
    ]);
    let value = snapshot(context);
    assert_eq!(value["builtin_packs"], json!(["base", "claude"]));
    assert_eq!(value["has_custom_packs"], true);
    assert!(!value.to_string().contains("private"));
    assert!(!value.to_string().contains("secret"));
    assert!(validator().is_valid(&value));
}

#[test]
fn pack_membership_requires_both_matching_bytes_and_bundled_location() {
    for (bytes, location, custom) in [
        (BASE, Some(true), false),
        (b"edited".as_slice(), Some(true), true),
        (BASE, Some(false), true),
        (b"edited".as_slice(), None, true),
    ] {
        let mut context = builder();
        context.packs([pack(Some("base"), bytes, location)]);
        let value = snapshot(context);
        assert_eq!(
            value["builtin_packs"],
            if custom { json!([]) } else { json!(["base"]) }
        );
        assert_eq!(value["has_custom_packs"], custom);
    }
}

#[test]
fn adding_a_grammar_changes_a_catalog_pack() {
    for grammar in [b"".as_slice(), b"version = 1\n", b"version = 2\n"] {
        let mut context = builder();
        context.packs([Pack {
            grammar: Some(grammar),
            ..pack(Some("base"), BASE, Some(true))
        }]);
        let value = snapshot(context);
        assert_eq!(value["builtin_packs"], json!([]));
        assert_eq!(value["has_custom_packs"], true);
    }
}

#[test]
fn unknown_pack_location_replaces_a_previous_graph_with_null() {
    let mut known = builder();
    known.packs([pack(Some("base"), BASE, Some(true))]);
    assert_eq!(snapshot(known)["builtin_packs"], json!(["base"]));
    let mut context = builder();
    context.packs([pack(Some("base"), BASE, Some(true))]);
    context.packs([
        pack(Some("base"), BASE, Some(true)),
        pack(Some("claude"), CLAUDE, None),
        pack(None, b"custom", Some(false)),
    ]);
    let value = snapshot(context);
    assert_eq!(value["builtin_packs"], Value::Null);
    assert_eq!(value["has_custom_packs"], Value::Null);
}

#[test]
fn resolved_empty_graph_is_known_empty() {
    let mut context = builder();
    context.packs([]);
    let value = snapshot(context);
    assert_eq!(value["builtin_packs"], json!([]));
    assert_eq!(value["has_custom_packs"], false);
}

#[test]
fn context_enums_cover_the_schema_exactly() {
    // Each match is exhaustive, so a new variant does not compile until it is listed here.
    let families = [
        OsFamily::Macos,
        OsFamily::Linux,
        OsFamily::Windows,
        OsFamily::Other,
    ];
    for family in &families {
        match family {
            OsFamily::Macos | OsFamily::Linux | OsFamily::Windows | OsFamily::Other => {}
        }
    }
    assert_eq!(
        serialized(&families),
        schema_enum("/definitions/run_context/properties/os_family")
    );
    let arches = [BuildArch::Aarch64, BuildArch::X86_64, BuildArch::Other];
    for arch in &arches {
        match arch {
            BuildArch::Aarch64 | BuildArch::X86_64 | BuildArch::Other => {}
        }
    }
    assert_eq!(
        serialized(&arches),
        schema_enum("/definitions/run_context/properties/build_arch")
    );
}

#[test]
fn os_version_is_trimmed_bounded_and_null_when_empty() {
    let long = "9".repeat(65);
    let wide = "é".repeat(65);
    for (reported, expected) in [
        (None, Value::Null),
        (Some(""), Value::Null),
        (Some(" \t\n"), Value::Null),
        (Some(" 22.04\n"), json!("22.04")),
        (Some(long.as_str()), json!("9".repeat(64))),
        (Some(wide.as_str()), json!("é".repeat(64))),
    ] {
        let context =
            RunContext::new("1.2.3", "linux", reported.map(str::to_owned), "x86_64").unwrap();
        let value = serde_json::to_value(context).unwrap();
        assert_eq!(value["os_version"], expected, "{reported:?}");
        assert!(validator().is_valid(&value), "{value}");
    }
}

#[test]
fn a_context_with_every_field_known_and_the_whole_catalog_fits_the_schema() {
    let mut context = RunContext::new("1.2.3", "macos", Some("14.5".into()), "aarch64").unwrap();
    context.builtin_packs = Some(CATALOG.keys().map(|id| (*id).to_owned()).collect());
    context.mcp_configured = Some(true);
    context.has_custom_packs = Some(true);
    context.profile_policy_present = Some(true);
    context.profile_hash = Some("0".repeat(64));
    let value = serde_json::to_value(context).unwrap();
    assert!(!CATALOG.is_empty());
    let errors: Vec<String> = validator()
        .iter_errors(&value)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
}
