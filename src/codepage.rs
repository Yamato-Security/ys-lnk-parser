//! Text in a Windows code page: what links, shell items and property stores
//! hold where they aren't Unicode, written in the code page the system was
//! set to (`HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage\ACP`), which
//! the data doesn't record.
//!
//! Windows-1252 (Western European, the default), Latin-1, ASCII and UTF-8
//! are built in. Other code pages (932 Japanese, 936 and 950 Chinese, 949
//! Korean, 1250–1258, …) need the `codepages` feature, which decodes with
//! `encoding_rs`; without it they're read as Windows-1252.

/// Windows-1252's characters for 0x80–0x9F. Its five unassigned bytes
/// (0x81, 0x8D, 0x8F, 0x90, 0x9D) map to the C1 control characters of the
/// same value, as Windows' `MultiByteToWideChar` maps them.
const CP1252_HIGH: [char; 32] = [
    '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8d}', 'Ž', '\u{8f}',
    '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9d}', 'ž', 'Ÿ',
];

/// `bytes` up to the first NUL, in code page `code_page`.
#[must_use]
pub fn decode(bytes: &[u8], code_page: u16) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let bytes = &bytes[..end];
    match code_page {
        28591 => bytes.iter().map(|&b| char::from(b)).collect(),
        20127 => bytes
            .iter()
            .map(|&b| if b < 0x80 { char::from(b) } else { '\u{fffd}' })
            .collect(),
        65001 => String::from_utf8_lossy(bytes).into_owned(),
        1252 => cp1252(bytes),
        other => other_code_page(bytes, other),
    }
}

fn cp1252(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0x80..=0x9f => CP1252_HIGH[usize::from(b - 0x80)],
            _ => char::from(b),
        })
        .collect()
}

#[cfg(feature = "codepages")]
fn other_code_page(bytes: &[u8], code_page: u16) -> String {
    match codepage::to_encoding(code_page) {
        Some(encoding) => encoding.decode_without_bom_handling(bytes).0.into_owned(),
        None => cp1252(bytes),
    }
}

#[cfg(not(feature = "codepages"))]
fn other_code_page(bytes: &[u8], _code_page: u16) -> String {
    cp1252(bytes)
}

/// Whether `code_page` is decoded as itself (not read as Windows-1252).
#[must_use]
pub fn is_supported(code_page: u16) -> bool {
    matches!(code_page, 1252 | 28591 | 20127 | 65001) || other_supported(code_page)
}

#[cfg(feature = "codepages")]
fn other_supported(code_page: u16) -> bool {
    codepage::to_encoding(code_page).is_some()
}

#[cfg(not(feature = "codepages"))]
fn other_supported(_code_page: u16) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_1252() {
        assert_eq!(decode(b"caf\xe9 \x80 \x93q\x94\0rest", 1252), "café € “q”");
        assert_eq!(decode(b"MZ\x90", 1252), "MZ\u{90}");
        assert_eq!(decode(b"\x81", 28591), "\u{81}");
        assert_eq!(decode(b"a\xe9", 20127), "a\u{fffd}");
        assert_eq!(decode("日本".as_bytes(), 65001), "日本");
        assert!(is_supported(1252));
    }

    #[cfg(feature = "codepages")]
    #[test]
    fn other_code_pages() {
        // "デスクトップ" (Desktop) in Shift-JIS
        let sjis = b"\x83\x66\x83\x58\x83\x4e\x83\x67\x83\x62\x83\x76";
        assert_eq!(decode(sjis, 932), "デスクトップ");
        assert_eq!(decode(b"\xcf\xf0\xe8\xe2\xe5\xf2", 1251), "Привет");
        assert!(is_supported(932));
    }

    #[cfg(not(feature = "codepages"))]
    #[test]
    fn other_code_pages_are_read_as_windows_1252() {
        assert_eq!(decode(b"\x83\x66", 932), "ƒf");
        assert!(!is_supported(932));
    }
}
