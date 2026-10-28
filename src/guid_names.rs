//! Names of the GUIDs shell items and links hold (root and known folders,
//! control panel pages, shell extensions, …), from Eric Zimmerman's
//! GuidMapping (MIT licence, `src/guid_names/LICENSE`; the table at
//! EricZimmerman/GuidMapping e2c9361), so that a folder the shell names by
//! a GUID gets the name his tools give it.
//!
//! Behind the `guid-names` feature (on by default): the table is about
//! 900 KB.

/// The name of `guid` (any case, with or without braces), if the table has
/// one: an exact entry, else the longest prefix of a family of GUIDs (a
/// OneDrive account's sync root, …).
#[must_use]
pub fn name(guid: &str) -> Option<&'static str> {
    lookup(&guid.trim_matches(['{', '}']).to_ascii_lowercase())
}

#[cfg(feature = "guid-names")]
fn lookup(guid: &str) -> Option<&'static str> {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();
    static PREFIXES: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();
    let pairs = |text: &'static str| -> Vec<(&'static str, &'static str)> {
        text.lines().filter_map(|l| l.split_once('|')).collect()
    };
    // Sorted by GUID in the file.
    let table = TABLE.get_or_init(|| pairs(include_str!("guid_names/guids.txt")));
    if let Ok(i) = table.binary_search_by(|(g, _)| (*g).cmp(guid)) {
        return Some(table[i].1);
    }
    let prefixes = PREFIXES.get_or_init(|| {
        let mut p = pairs(include_str!("guid_names/prefixes.txt"));
        p.sort_by_key(|(prefix, _)| std::cmp::Reverse(prefix.len()));
        p
    });
    prefixes
        .iter()
        .find(|(prefix, _)| guid.starts_with(prefix))
        .map(|(_, name)| *name)
}

#[cfg(not(feature = "guid-names"))]
fn lookup(_guid: &str) -> Option<&'static str> {
    None
}

#[cfg(all(test, feature = "guid-names"))]
mod tests {
    use super::name;

    #[test]
    fn names() {
        assert_eq!(
            name("{208D2C60-3AEA-1069-A2D7-08002B30309D}"),
            Some("Network")
        );
        assert_eq!(
            name("f02c1a0d-be21-4350-88b0-7367fc96ef3c"),
            Some("Computers and Devices")
        );
        assert_eq!(
            name("{04271989-0000-0000-0000-000000000000}"),
            Some("OneDrive (per-account sync root)")
        );
        assert_eq!(name("{00000000-1111-2222-3333-444444444444}"), None);
    }
}
