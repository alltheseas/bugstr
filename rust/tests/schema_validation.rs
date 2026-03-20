//! Schema validation tests for bugstr's Nostr event construction.
//!
//! Validates that events produced by bugstr conform to the canonical
//! nostrability/schemata definitions. These run in CI to catch schema
//! drift at build time rather than at runtime.

use bugstr::UnsignedNostrEvent;
use schemata_validator_rs::{validate, validate_note, get_schema};

fn hex64(c: char) -> String {
    std::iter::repeat(c).take(64).collect()
}

fn sig128(c: char) -> String {
    std::iter::repeat(c).take(128).collect()
}

/// Convert an UnsignedNostrEvent to schema-valid JSON.
///
/// Bugstr includes `sig: ""` in rumor JSON for client compatibility (0xchat etc),
/// but NIP-17 schemata says `sig` must NOT be present on unsigned events.
/// Strip it before schema validation.
fn to_schema_value(event: &UnsignedNostrEvent) -> serde_json::Value {
    let mut value = serde_json::to_value(event).unwrap();
    if let Some(obj) = value.as_object_mut() {
        obj.remove("sig");
    }
    value
}

// -- Kind 14: NIP-17 Rumor (unsigned DM) --

#[test]
fn kind14_rumor_validates() {
    let event = UnsignedNostrEvent::new(
        hex64('a'),
        1700000000,
        14,
        vec![vec!["p".into(), hex64('b')]],
        "crash report payload",
    )
    .with_id();

    let value = to_schema_value(&event);
    let result = validate_note(&value);

    assert!(
        result.valid,
        "kind 14 rumor should validate. errors: {:?}",
        result.errors
    );
}

#[test]
fn kind14_rumor_with_reply_tag_validates() {
    let event = UnsignedNostrEvent::new(
        hex64('a'),
        1700000000,
        14,
        vec![
            vec!["p".into(), hex64('b')],
            vec!["e".into(), hex64('c'), "wss://relay.example.com".into(), "reply".into()],
        ],
        "crash report payload",
    )
    .with_id();

    let value = to_schema_value(&event);
    let result = validate_note(&value);

    assert!(
        result.valid,
        "kind 14 rumor with reply tag should validate. errors: {:?}",
        result.errors
    );
}

// -- Kind 1: basic note (smoke test that validator works) --

#[test]
fn kind1_note_validates() {
    let note = serde_json::json!({
        "id": hex64('a'),
        "pubkey": hex64('b'),
        "created_at": 1700000000u64,
        "kind": 1,
        "tags": [],
        "content": "hello world",
        "sig": sig128('c')
    });

    let result = validate_note(&note);

    assert!(
        result.valid,
        "kind 1 note should validate. errors: {:?}",
        result.errors
    );
}

// -- Tag schema validation --

#[test]
fn p_tag_validates() {
    let schema = get_schema("pTagSchema").expect("pTagSchema should exist");
    let tag = serde_json::json!(["p", hex64('a')]);
    let result = validate(schema, &tag);

    assert!(
        result.valid,
        "p tag should validate. errors: {:?}",
        result.errors
    );
}

#[test]
fn e_tag_validates() {
    let schema = get_schema("eTagSchema").expect("eTagSchema should exist");
    let tag = serde_json::json!(["e", hex64('a'), "wss://relay.example.com", "reply"]);
    let result = validate(schema, &tag);

    assert!(
        result.valid,
        "e tag should validate. errors: {:?}",
        result.errors
    );
}

// -- Test vector: event ID computation --

#[test]
fn event_id_matches_test_vectors() {
    let vectors = vec![
        (
            "simple_rumor_no_tags",
            hex64('a'),
            1234567890u64,
            14u16,
            vec![],
            "test",
            "1bc0c6ea8e0a72276ebeaf1c722028dc8b0841c09b141174bd5976adfe67a65d",
        ),
        (
            "rumor_with_p_tag",
            hex64('a'),
            1234567890,
            14,
            vec![vec!["p".into(), hex64('b')]],
            "hello world",
            "34286c63206447cb43d92f93054e8edfc275211fe830c0549daabf578bb8c3f8",
        ),
        (
            "content_with_special_chars",
            hex64('a'),
            1234567890,
            14,
            vec![],
            "line1\nline2\ttab\"quote\\backslash",
            "e1e055550ce8cf02766370d7a513888134f7e14d72050b6d76ddb40d57aafcbc",
        ),
    ];

    for (name, pubkey, created_at, kind, tags, content, expected_id) in vectors {
        let event = UnsignedNostrEvent::new(pubkey, created_at, kind, tags, content);
        let computed = event.compute_id();
        assert_eq!(
            computed, expected_id,
            "ID mismatch for vector '{}'",
            name
        );
    }
}

// -- Negative tests: invalid events should fail --

#[test]
fn wrong_kind_fails_validation() {
    let note = serde_json::json!({
        "id": hex64('a'),
        "pubkey": hex64('b'),
        "created_at": 1700000000u64,
        "kind": 1,
        "tags": [],
        "content": "hello",
        "sig": sig128('c')
    });

    let schema = get_schema("kind0Schema").expect("kind0Schema should exist");
    let result = validate(schema, &note);
    assert!(
        !result.valid,
        "kind 1 note should fail kind 0 schema validation"
    );
}

#[test]
fn missing_pubkey_fails_validation() {
    let note = serde_json::json!({
        "id": hex64('a'),
        "created_at": 1700000000u64,
        "kind": 1,
        "tags": [],
        "content": "hello",
        "sig": sig128('c')
    });

    let schema = get_schema("noteSchema").expect("noteSchema should exist");
    let result = validate(schema, &note);
    assert!(
        !result.valid,
        "event missing pubkey should fail validation"
    );
}
