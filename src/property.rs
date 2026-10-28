//! Serialized property stores (MS-PROPSTORE): what a link's property store
//! block and some shell items hold, such as a target's parsing path, the
//! app user model ID of a pinned app, or a display name.
//!
//! A store is a sequence of storages (`1SPS`), each of one property set
//! (its format identifier) and the values in it, by number, or by name for
//! the string-named set `{D5CDD505-2E9C-101B-9397-08002B2CF9AE}`. Values are
//! typed (MS-OLEPS `TypedPropertyValue`): integers, floating point numbers,
//! booleans, strings, times, GUIDs, blobs and vectors of these.

use std::fmt::Write;

use crate::codepage;
use crate::item::guid;
use crate::{u16_at, u32_at, u64_at};

/// The property set whose values are named rather than numbered.
const NAMED_SET: &str = "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}";
/// The most elements a vector may have: each takes at least 1 byte.
const MAX_ELEMENTS: usize = 1 << 16;

/// One property of a store.
#[derive(Debug, Clone, PartialEq)]
pub struct Property {
    /// The property set's format identifier (`{B725F130-…}`).
    pub format_id: String,
    /// The property's number in its set (0 for a named property).
    pub id: u32,
    /// The property's name, in the string-named set.
    pub name: Option<String>,
    /// Its value.
    pub value: Value,
}

impl Property {
    /// The property's canonical name, for well-known ones:
    /// `System.ItemNameDisplay`, `System.Link.TargetParsingPath`, ….
    #[must_use]
    pub fn canonical_name(&self) -> Option<&'static str> {
        canonical_name(&self.format_id, self.id)
    }
}

/// A typed property value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `VT_EMPTY` or `VT_NULL`.
    Empty,
    /// `VT_BOOL`.
    Bool(bool),
    /// A signed integer (`VT_I1`, `VT_I2`, `VT_I4`, `VT_INT`, `VT_I8`,
    /// `VT_CY`, `VT_ERROR`).
    Int(i64),
    /// An unsigned integer (`VT_UI1`, `VT_UI2`, `VT_UI4`, `VT_UINT`,
    /// `VT_UI8`).
    UInt(u64),
    /// `VT_R4`, `VT_R8`, `VT_DATE` (an OLE automation date, in days).
    Float(f64),
    /// `VT_LPWSTR`, `VT_BSTR`, `VT_LPSTR`.
    Text(String),
    /// `VT_FILETIME` (100 ns since 1601).
    Time(u64),
    /// `VT_CLSID`.
    Guid(String),
    /// `VT_BLOB` and other bytes.
    Bytes(Vec<u8>),
    /// `VT_VECTOR` of a type.
    List(Vec<Value>),
    /// A type not decoded here (`VT_STREAM`, `VT_ARRAY`, …): its number.
    Unsupported(u16),
}

impl Value {
    /// The value as text, for display: lists joined with `; `, times and
    /// bytes as numbers and hex.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Value::Empty => String::new(),
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::UInt(n) | Value::Time(n) => n.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Text(s) | Value::Guid(s) => s.clone(),
            Value::Bytes(b) => b.iter().fold(String::new(), |mut hex, x| {
                let _ = write!(hex, "{x:02x}");
                hex
            }),
            Value::List(values) => values
                .iter()
                .map(Value::display)
                .collect::<Vec<_>>()
                .join("; "),
            Value::Unsupported(t) => format!("(type {t:#06x})"),
        }
    }
}

/// The properties of a serialized property store, in order. Damage ends
/// the storage it's in; a storage whose size is out of range is skipped to
/// the next `1SPS` signature.
#[must_use]
pub fn parse(store: &[u8], code_page: u16) -> Vec<Property> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(size) = u32_at(store, at).map(|n| n as usize) {
        if size == 0 {
            break;
        }
        if size < 24 || at + size > store.len() || store.get(at + 4..at + 8) != Some(b"1SPS") {
            // Look for the next storage's signature, after this one's.
            let Some(next) = store
                .get(at + 5..)
                .and_then(|rest| rest.windows(4).position(|w| w == b"1SPS"))
            else {
                break;
            };
            at = at + 1 + next;
            continue;
        }
        storage(&store[at..at + size], code_page, &mut out);
        at += size;
    }
    out
}

fn storage(storage: &[u8], code_page: u16, out: &mut Vec<Property>) {
    let Some(format_id) = storage.get(8..24).and_then(guid) else {
        return;
    };
    let named = format_id == NAMED_SET;
    let mut at = 24;
    while let Some(size) = u32_at(storage, at).map(|n| n as usize) {
        if size == 0 || size < 9 || at + size > storage.len() {
            break;
        }
        let value = &storage[at..at + size];
        let (id, name, typed) = if named {
            let name_size = u32_at(value, 4).unwrap_or(0) as usize;
            let Some(name_bytes) = value.get(9..9 + name_size) else {
                break;
            };
            (0, Some(utf16(name_bytes)), value.get(9 + name_size..))
        } else {
            (u32_at(value, 4).unwrap_or(0), None, value.get(9..))
        };
        if let Some(typed) = typed {
            out.push(Property {
                format_id: format_id.clone(),
                id,
                name,
                value: typed_value(typed, code_page),
            });
        }
        at += size;
    }
}

/// A `TypedPropertyValue`: a 16-bit type, padding, then the value.
fn typed_value(data: &[u8], code_page: u16) -> Value {
    let Some(kind) = u16_at(data, 0) else {
        return Value::Empty;
    };
    let body = data.get(4..).unwrap_or_default();
    if kind & 0x1000 != 0 {
        return vector(kind & 0x0fff, body, code_page);
    }
    scalar(kind, body, code_page).map_or(Value::Unsupported(kind), |(v, _)| v)
}

/// A vector: a count, then the elements one after another, strings padded
/// to 4 bytes.
fn vector(kind: u16, body: &[u8], code_page: u16) -> Value {
    let count = u32_at(body, 0).map_or(0, |n| n as usize).min(MAX_ELEMENTS);
    let mut at = 4;
    let mut values = Vec::new();
    for _ in 0..count {
        let Some((value, used)) = body
            .get(at..)
            .and_then(|rest| scalar(kind, rest, code_page))
        else {
            break;
        };
        values.push(value);
        at += used;
    }
    Value::List(values)
}

/// A value of `kind` at the start of `data`, and how many bytes it takes.
fn scalar(kind: u16, data: &[u8], code_page: u16) -> Option<(Value, usize)> {
    let int = |n: i64, used| Some((Value::Int(n), used));
    let uint = |n: u64, used| Some((Value::UInt(n), used));
    match kind {
        0 | 1 => Some((Value::Empty, 0)),
        0x10 => int(i64::from(*data.first()? as i8), 1),
        0x11 => uint(u64::from(*data.first()?), 1),
        2 => int(i64::from(u16_at(data, 0)? as i16), 2),
        0x12 => uint(u64::from(u16_at(data, 0)?), 2),
        3 | 0x16 | 0x0a => int(i64::from(u32_at(data, 0)? as i32), 4),
        0x13 | 0x17 => uint(u64::from(u32_at(data, 0)?), 4),
        0x14 | 6 => int(u64_at(data, 0)? as i64, 8),
        0x15 => uint(u64_at(data, 0)?, 8),
        4 => Some((Value::Float(f64::from(f32::from_bits(u32_at(data, 0)?))), 4)),
        5 | 7 => Some((Value::Float(f64::from_bits(u64_at(data, 0)?)), 8)),
        0x0b => Some((Value::Bool(u16_at(data, 0)? != 0), 2)),
        0x40 => Some((Value::Time(u64_at(data, 0)?), 8)),
        0x48 => Some((Value::Guid(guid(data.get(..16)?)?), 16)),
        // VT_LPWSTR: a character count (with the NUL), then UTF-16.
        0x1f => {
            let chars = u32_at(data, 0)? as usize;
            let bytes = data.get(4..4 + chars.checked_mul(2)?)?;
            Some((Value::Text(utf16(bytes)), pad4(4 + 2 * chars)))
        }
        // VT_BSTR: a size in bytes, then UTF-16 (property stores are
        // Unicode); VT_LPSTR: a size, then code page text.
        8 | 0x1e => {
            let size = u32_at(data, 0)? as usize;
            let bytes = data.get(4..4 + size)?;
            let text = if kind == 8 {
                utf16(bytes)
            } else {
                codepage::decode(bytes, code_page)
            };
            Some((Value::Text(text), pad4(4 + size)))
        }
        // VT_BLOB
        0x41 => {
            let size = u32_at(data, 0)? as usize;
            Some((
                Value::Bytes(data.get(4..4 + size)?.to_vec()),
                pad4(4 + size),
            ))
        }
        _ => None,
    }
}

fn pad4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Canonical names of well-known properties (Windows SDK `propkey.h`).
#[must_use]
pub fn canonical_name(format_id: &str, id: u32) -> Option<&'static str> {
    Some(match (format_id, id) {
        ("{B725F130-47EF-101A-A5F1-02608C9EEBAC}", 2) => "System.ItemFolderNameDisplay",
        ("{B725F130-47EF-101A-A5F1-02608C9EEBAC}", 4) => "System.ItemTypeText",
        ("{B725F130-47EF-101A-A5F1-02608C9EEBAC}", 10) => "System.ItemNameDisplay",
        ("{B725F130-47EF-101A-A5F1-02608C9EEBAC}", 12) => "System.Size",
        ("{B725F130-47EF-101A-A5F1-02608C9EEBAC}", 13) => "System.FileAttributes",
        ("{B725F130-47EF-101A-A5F1-02608C9EEBAC}", 14) => "System.DateModified",
        ("{B725F130-47EF-101A-A5F1-02608C9EEBAC}", 15) => "System.DateCreated",
        ("{B725F130-47EF-101A-A5F1-02608C9EEBAC}", 16) => "System.DateAccessed",
        ("{28636AA6-953D-11D2-B5D6-00C04FD918D0}", 5) => "System.ComputerName",
        ("{28636AA6-953D-11D2-B5D6-00C04FD918D0}", 30) => "System.ParsingPath",
        ("{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}", 2) => "System.AppUserModel.RelaunchCommand",
        ("{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}", 3) => "System.AppUserModel.RelaunchIconResource",
        ("{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}", 4) => {
            "System.AppUserModel.RelaunchDisplayNameResource"
        }
        ("{9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3}", 5) => "System.AppUserModel.ID",
        ("{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}", 2) => "System.Link.TargetParsingPath",
        ("{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}", 8) => "System.Link.TargetSFGAOFlags",
        ("{446D16B1-8DAD-4870-A748-402EA43D788C}", 100) => "System.ThumbnailCacheId",
        ("{446D16B1-8DAD-4870-A748-402EA43D788C}", 104) => "System.VolumeId",
        ("{DABD30ED-0043-4789-A7F8-D013A4736622}", 100) => "System.ItemFolderPathDisplayNarrow",
        ("{E3E0584C-B788-4A5A-BB20-7F5A44C9ACDD}", 6) => "System.ItemFolderPathDisplay",
        ("{E3E0584C-B788-4A5A-BB20-7F5A44C9ACDD}", 7) => "System.ItemPathDisplay",
        ("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 2) => "System.Title",
        ("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 3) => "System.Subject",
        ("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 4) => "System.Author",
        ("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 5) => "System.Keywords",
        ("{F29F85E0-4FF9-1068-AB91-08002B27B3D9}", 6) => "System.Comment",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(id: u32, typed: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((9 + typed.len()) as u32).to_le_bytes());
        v.extend_from_slice(&id.to_le_bytes());
        v.push(0);
        v.extend_from_slice(typed);
        v
    }

    fn storage(fmtid: [u8; 16], values: &[Vec<u8>]) -> Vec<u8> {
        let mut s = vec![0; 4];
        s.extend_from_slice(b"1SPS");
        s.extend_from_slice(&fmtid);
        for v in values {
            s.extend_from_slice(v);
        }
        s.extend_from_slice(&0u32.to_le_bytes());
        let n = s.len() as u32;
        s[..4].copy_from_slice(&n.to_le_bytes());
        s
    }

    const STORAGE_SET: [u8; 16] = [
        0x30, 0xf1, 0x25, 0xb7, 0xef, 0x47, 0x1a, 0x10, 0xa5, 0xf1, 0x02, 0x60, 0x8c, 0x9e, 0xeb,
        0xac,
    ];

    fn lpwstr(text: &str) -> Vec<u8> {
        let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
        let mut t = vec![0x1f, 0, 0, 0];
        t.extend_from_slice(&(units.len() as u32).to_le_bytes());
        for u in units {
            t.extend_from_slice(&u.to_le_bytes());
        }
        t
    }

    #[test]
    fn numbered_values_of_each_type() {
        let mut filetime = vec![0x40, 0, 0, 0];
        filetime.extend_from_slice(&132_885_610_136_531_487u64.to_le_bytes());
        let mut size = vec![0x15, 0, 0, 0];
        size.extend_from_slice(&4096u64.to_le_bytes());
        let mut vector = vec![0x1f, 0x10, 0, 0]; // VT_VECTOR | VT_LPWSTR
        vector.extend_from_slice(&2u32.to_le_bytes());
        for word in ["a", "bcd"] {
            let units: Vec<u16> = word.encode_utf16().chain([0]).collect();
            vector.extend_from_slice(&(units.len() as u32).to_le_bytes());
            let mut bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
            bytes.resize(bytes.len().div_ceil(4) * 4, 0);
            vector.extend_from_slice(&bytes);
        }
        let store = storage(
            STORAGE_SET,
            &[
                value(10, &lpwstr("report.docx")),
                value(14, &filetime),
                value(12, &size),
                value(99, &[0x0b, 0, 0, 0, 0xff, 0xff]),
                value(98, &vector),
                value(97, &[0x42, 0, 0, 0]),
            ],
        );
        let props = parse(&store, 1252);
        let values: Vec<_> = props.iter().map(|p| (p.id, p.value.clone())).collect();
        assert_eq!(
            values,
            [
                (10, Value::Text("report.docx".into())),
                (14, Value::Time(132_885_610_136_531_487)),
                (12, Value::UInt(4096)),
                (99, Value::Bool(true)),
                (
                    98,
                    Value::List(vec![Value::Text("a".into()), Value::Text("bcd".into())])
                ),
                (97, Value::Unsupported(0x42)),
            ]
        );
        assert_eq!(props[0].canonical_name(), Some("System.ItemNameDisplay"));
        assert_eq!(props[0].format_id, "{B725F130-47EF-101A-A5F1-02608C9EEBAC}");
    }

    #[test]
    fn named_values_and_damage() {
        // the string-named set: a name, then the typed value
        let named_set = [
            0x05, 0xd5, 0xcd, 0xd5, 0x9c, 0x2e, 0x1b, 0x10, 0x93, 0x97, 0x08, 0x00, 0x2b, 0x2c,
            0xf9, 0xae,
        ];
        let name: Vec<u8> = "Owner\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut v = Vec::new();
        let typed = lpwstr("alice");
        v.extend_from_slice(&((9 + name.len() + typed.len()) as u32).to_le_bytes());
        v.extend_from_slice(&(name.len() as u32).to_le_bytes());
        v.push(0);
        v.extend_from_slice(&name);
        v.extend_from_slice(&typed);
        let mut store = storage(named_set, &[v]);
        // a damaged storage (its size runs past the end), then a good one
        let mut damaged = storage(STORAGE_SET, &[value(10, &lpwstr("lost"))]);
        damaged[..4].copy_from_slice(&0x00ff_ffffu32.to_le_bytes());
        store.extend_from_slice(&damaged);
        store.extend_from_slice(&storage(STORAGE_SET, &[value(10, &lpwstr("found"))]));
        let props = parse(&store, 1252);
        assert_eq!(props.len(), 2);
        assert_eq!(props[0].name.as_deref(), Some("Owner"));
        assert_eq!(props[0].value, Value::Text("alice".into()));
        assert_eq!(props[1].value, Value::Text("found".into()));
        // truncated and empty stores
        assert_eq!(parse(&store[..30], 1252), []);
        assert_eq!(parse(&[], 1252), []);
        // a vector count far beyond the data
        let mut huge = vec![0x13, 0x10, 0, 0];
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        huge.extend_from_slice(&7u32.to_le_bytes());
        let props = parse(&storage(STORAGE_SET, &[value(5, &huge)]), 1252);
        assert_eq!(props[0].value, Value::List(vec![Value::UInt(7)]));
    }
}
