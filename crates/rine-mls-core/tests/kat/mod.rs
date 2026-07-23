// Each test binary that reads a fixture compiles this module separately and
// uses a different slice of it.
#![allow(dead_code)]

//! Reader for the committed known-answer fixtures.
//!
//! The format is deliberately dull — `name hex` lines, blank-line separated
//! records — so a reviewer can diff a fixture without a parser, and so a
//! dependency bump that changes any byte fails as a plain value mismatch.

use std::collections::BTreeMap;

pub struct Record {
    pub label: String,
    fields: BTreeMap<String, Vec<u8>>,
}

impl Record {
    /// Field as raw bytes. A missing field is a broken fixture, not a test
    /// condition, so it panics rather than returning an option nobody handles.
    pub fn bytes(&self, name: &str) -> &[u8] {
        self.fields
            .get(name)
            .unwrap_or_else(|| panic!("fixture record `{}` has no field `{name}`", self.label))
    }

    pub fn array<const N: usize>(&self, name: &str) -> [u8; N] {
        self.bytes(name).try_into().unwrap_or_else(|_| {
            panic!(
                "fixture record `{}` field `{name}` is {} bytes, expected {N}",
                self.label,
                self.bytes(name).len(),
            )
        })
    }
}

pub fn parse(fixture: &str) -> Vec<Record> {
    let mut records: Vec<Record> = Vec::new();

    for line in fixture.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (name, value) = line
            .split_once(' ')
            .unwrap_or_else(|| panic!("malformed fixture line: {line}"));

        // A record header opens a new record; every other line is a field of
        // the record currently being read.
        if name == "vector" {
            records.push(Record {
                label: value.to_owned(),
                fields: BTreeMap::new(),
            });
            continue;
        }

        let bytes = hex::decode(value).unwrap_or_else(|e| panic!("bad hex for `{name}`: {e}"));

        records
            .last_mut()
            .unwrap_or_else(|| panic!("field `{name}` appears before any `vector` header"))
            .fields
            .insert(name.to_owned(), bytes);
    }

    assert!(!records.is_empty(), "fixture contains no vectors");

    records
}
