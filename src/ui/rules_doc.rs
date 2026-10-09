//! Pure, comment-preserving conversion between `05-web.toml` and the UI's rule drafts.

use crate::policy::{RuleFileError, RuleSet};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table};

/// The label used for rule identifiers when validating UI edits.
const WEB_RULES_LABEL: &str = "05-web.toml";

/// One editable allow table, referencing its original table to retain comments.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    /// The table's position in the original document, or `None` for a new rule.
    pub index: Option<usize>,
    /// Field values as ordinary JSON-compatible TOML values.
    pub fields: BTreeMap<String, toml::Value>,
}

/// The rules document; the original text acts as a revision token for optimistic concurrency.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RulesDocument {
    /// The exact file contents the drafts were read from.
    pub revision: String,
    /// The allow tables in document order.
    pub rules: Vec<Draft>,
}

/// A rules document that cannot be read or edited.
#[derive(Debug, Error)]
pub enum RulesDocError {
    /// The document is not valid TOML for format-preserving editing.
    #[error("parse 05-web.toml")]
    Syntax(#[from] toml_edit::TomlError),
    /// The document's values could not be decoded.
    #[error("decode 05-web.toml")]
    Values(#[from] toml::de::Error),
    /// `allow` is not an array of tables.
    #[error("allow must be an array of rule tables")]
    NotTables,
    /// A draft references the same original table twice.
    #[error("duplicate original rule index")]
    DuplicateIndex,
    /// A draft references a table that does not exist.
    #[error("unknown original rule index")]
    UnknownIndex,
    /// A field value could not be rendered as TOML.
    #[error("render rule field")]
    Render(#[from] toml_edit::ser::Error),
    /// A rendered field is not a plain value.
    #[error("expected a TOML value")]
    NotAValue,
    /// The edited rules fail validation.
    #[error(transparent)]
    Invalid(#[from] RuleFileError),
}

/// Extract the `allow` array of tables, or an empty array when absent.
fn allow_tables(document: &DocumentMut) -> Result<ArrayOfTables, RulesDocError> {
    match document.get("allow") {
        Some(item) => item.clone().into_array_of_tables().map_err(|_| RulesDocError::NotTables),
        None => Ok(ArrayOfTables::new()),
    }
}

/// Read field values while retaining the original document as the revision.
pub fn read_document(revision: String) -> Result<RulesDocument, RulesDocError> {
    let document = revision.parse::<DocumentMut>()?;
    let values: toml::Value = toml::from_str(&revision)?;
    let mut rules = Vec::new();
    for (index, table) in allow_tables(&document)?.iter().enumerate() {
        let mut fields = BTreeMap::new();
        for (key, _) in table {
            let value = values
                .get("allow")
                .and_then(|rules| rules.get(index))
                .and_then(|rule| rule.get(key))
                .ok_or(RulesDocError::NotTables)?;
            fields.insert(key.to_owned(), value.clone());
        }
        rules.push(Draft {
            index: Some(index),
            fields,
        });
    }
    Ok(RulesDocument {
        revision,
        rules,
    })
}

/// Render one JSON-compatible field value as a TOML item.
fn render(field: &toml::Value) -> Result<Item, RulesDocError> {
    let wrapper = BTreeMap::from([("value", field)]);
    let rendered = toml_edit::ser::to_document(&wrapper)?;
    let value = rendered.get("value").ok_or(RulesDocError::NotAValue)?.clone();
    if !value.is_value() {
        return Err(RulesDocError::NotAValue);
    }
    Ok(value)
}

/// Rebuild edited tables while preserving unchanged items, then validate the result.
pub fn edit_document(draft: &RulesDocument) -> Result<String, RulesDocError> {
    let mut document = draft.revision.parse::<DocumentMut>()?;
    let original = allow_tables(&document)?;
    let original_values: toml::Value = toml::from_str(&draft.revision)?;
    let mut tables = ArrayOfTables::new();
    let mut indices = HashSet::new();
    for rule in &draft.rules {
        let mut table = match rule.index {
            Some(index) => {
                if !indices.insert(index) {
                    return Err(RulesDocError::DuplicateIndex);
                }
                original.get(index).ok_or(RulesDocError::UnknownIndex)?.clone()
            }
            None => Table::new(),
        };
        table.retain(|key, _| rule.fields.contains_key(key));
        let original_rule = original_values
            .get("allow")
            .and_then(|rules| rule.index.and_then(|index| rules.get(index)));
        for (key, field) in &rule.fields {
            // Semantically unchanged fields retain their original comments and syntax.
            if original_rule.and_then(|original| original.get(key)) == Some(field) {
                continue;
            }
            let mut value = render(field)?;
            if let (Some(old), Some(new)) =
                (table.get(key).and_then(Item::as_value), value.as_value_mut())
            {
                *new.decor_mut() = old.decor().clone();
            }
            if let Some(existing) = table.get_mut(key) {
                *existing = value;
            } else {
                table.insert(key, value);
            }
        }
        tables.push(table);
    }
    if tables.is_empty() {
        document.remove("allow");
    } else {
        document["allow"] = Item::ArrayOfTables(tables);
    }
    let edited = document.to_string();
    RuleSet::parse(&edited, WEB_RULES_LABEL)?;
    Ok(edited)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip plain JSON strings, lists, booleans, and headers without user-supplied escaping.
    #[test]
    fn edits_serialize_typed_values_and_preserve_unchanged_documents() {
        let fields = serde_json::json!({
            "domain_regex": [r"^one\.test$", r"^two\.test$"],
            "methods": ["GET", "POST"],
            "pathname_pattern": "/api/*",
            "pathname_regex": "^/api/",
            "stream": false,
            "inject_headers": [{"name": "X-Example", "value": "a \"quoted\" value \\ suffix"}]
        });
        let draft: RulesDocument = serde_json::from_value(serde_json::json!({
            "revision": "",
            "rules": [{"index": null, "fields": fields}]
        }))
        .unwrap();
        let saved = edit_document(&draft).unwrap();
        let parsed: toml::Value = toml::from_str(&saved).unwrap();
        assert_eq!(serde_json::to_value(&parsed["allow"][0]).unwrap(), fields);
        let read = read_document(saved.clone()).unwrap();
        assert_eq!(serde_json::to_value(&read.rules[0].fields).unwrap(), fields);
        assert_eq!(edit_document(&read).unwrap(), saved);

        let mut changed = read;
        changed.rules[0].fields.insert("methods".into(), "ANY".into());
        changed.rules[0].fields.remove("domain_regex");
        changed.rules[0].fields.insert("domain".into(), "example.com".into());
        changed.rules[0].fields.insert("include_subdomains".into(), true.into());
        let saved = edit_document(&changed).unwrap();
        let parsed: toml::Value = toml::from_str(&saved).unwrap();
        assert_eq!(parsed["allow"][0]["methods"].as_str(), Some("ANY"));
        assert_eq!(parsed["allow"][0]["domain"].as_str(), Some("example.com"));
        assert_eq!(parsed["allow"][0]["include_subdomains"].as_bool(), Some(true));
    }

    /// Comments, unchanged syntax, and nested header tables survive an edit of another field.
    #[test]
    fn preserves_comments_and_formatting() {
        let original = "# Web rules\n[[allow]]\n# Host comment\ndomain = 'old.test' # Keep this\nmethods = ['GET']\n[[allow.inject_headers]]\nname = 'X-Example'\nvalue = 'original'\n";
        let mut draft = read_document(original.into()).unwrap();
        assert_eq!(draft.rules[0].fields["domain"].as_str(), Some("old.test"));
        assert_eq!(draft.rules[0].fields["inject_headers"][0]["name"].as_str(), Some("X-Example"));
        draft.rules[0].fields.insert("domain".into(), "new.test".into());
        let saved = edit_document(&draft).unwrap();
        assert!(saved.contains("# Web rules"));
        assert!(saved.contains("# Host comment"));
        assert!(saved.contains("domain = \"new.test\" # Keep this"));
        assert!(saved.contains("methods = ['GET']"));
        assert!(saved.contains("[[allow.inject_headers]]"));
    }

    /// Invalid rules, bad indices, and non-table documents are rejected without output.
    #[test]
    fn rejects_invalid_edits() {
        let original = "[[allow]]\ndomain = 'a.test'\n";
        let mut draft = read_document(original.into()).unwrap();
        draft.rules[0].fields.insert("domain_regex".into(), "[".into());
        assert!(matches!(edit_document(&draft), Err(RulesDocError::Invalid(_))));
        let mut duplicate = read_document(original.into()).unwrap();
        duplicate.rules.push(duplicate.rules[0].clone());
        assert!(matches!(edit_document(&duplicate), Err(RulesDocError::DuplicateIndex)));
        let mut unknown = read_document(original.into()).unwrap();
        unknown.rules[0].index = Some(5);
        assert!(matches!(edit_document(&unknown), Err(RulesDocError::UnknownIndex)));
        assert!(matches!(read_document("allow = 1".into()), Err(RulesDocError::NotTables)));
        let mut cleared = read_document(original.into()).unwrap();
        cleared.rules.clear();
        assert_eq!(edit_document(&cleared).unwrap(), "");
    }
}
