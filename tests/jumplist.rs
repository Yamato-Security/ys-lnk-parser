//! Jump lists against a reference jump list parser (its output in
//! `tests/fixtures/oracle/`), on the MIT test set (automatic jump lists
//! from Windows 7, 8.0, 8.1 and 10), plaso's Apache-2.0 test data
//! (automatic and custom) and a synthetic custom one: every `DestList`
//! column, and the link columns of each entry.
//!
//! The oracle names only the first category of a custom jump list; later
//! ones are checked against their bytes by hand.

mod common;

use std::collections::HashMap;
use std::fs;

use common::{fixtures, path_agrees, records, when};
use shell::jumplist::{self, Destination, Kind};
use shell::lnk::Link;

const FILES: [&str; 8] = [
    "Win10/7e4dca80246863e3.automaticDestinations-ms",
    "Win10/f01b4d95cf55d32a.automaticDestinations-ms",
    "Win10/5f7b5f1e01b83767.automaticDestinations-ms",
    "Win7/1b4dd67f29cb1962.automaticDestinations-ms",
    "Win80/f01b4d95cf55d32a.automaticDestinations-ms",
    "Win81/f01b4d95cf55d32a.automaticDestinations-ms",
    "plaso/1b4dd67f29cb1962.automaticDestinations-ms",
    "plaso/9d1f905ce5044aee.automaticDestinations-ms",
];

const CUSTOM: [&str; 3] = [
    "plaso/368d807282ccde9d.customDestinations-ms",
    "plaso/5afe4de1b92fc382.customDestinations-ms",
    "synthetic/ccba5a5986c77e43.customDestinations-ms",
];

/// A GUID as the oracle prints it: lowercase, no braces.
fn bare(guid: &str) -> String {
    guid.trim_matches(['{', '}']).to_ascii_lowercase()
}

fn link_columns(link: &Link) -> Vec<(&'static str, String)> {
    let tracker = link.tracker.as_ref();
    vec![
        ("TargetCreated", when(link.created)),
        ("TargetModified", when(link.modified)),
        ("TargetAccessed", when(link.accessed)),
        ("FileSize", link.size.to_string()),
        ("LocalPath", link.local_path.clone()),
        ("Arguments", link.arguments.clone()),
        (
            "MachineID",
            tracker.map_or(String::new(), |t| t.machine_id.clone()),
        ),
        (
            "MachineMACAddress",
            tracker.map_or(String::new(), |t| t.mac.clone()),
        ),
    ]
}

fn check_link(link: &Link, row: &HashMap<String, String>, at: &str) {
    for (column, value) in link_columns(link) {
        assert_eq!(&value, &row[column], "{at}: {column}");
    }
    let target = link.target_path();
    assert!(
        path_agrees(&row["TargetIDAbsolutePath"], &target),
        "{at}: {} vs {target}",
        row["TargetIDAbsolutePath"]
    );
}

fn oracle(name: &str) -> HashMap<String, Vec<HashMap<String, String>>> {
    let mut by_file: HashMap<String, Vec<_>> = HashMap::new();
    for row in records(&fs::read_to_string(fixtures().join("oracle").join(name)).unwrap()) {
        by_file
            .entry(row["SourceFile"].clone())
            .or_default()
            .push(row);
    }
    by_file
}

fn columns(d: &Destination, version: u32) -> Vec<(&'static str, String)> {
    vec![
        ("EntryNumber", d.entry.to_string()),
        ("DestListVersion", version.to_string()),
        ("LastModified", when(d.last_used)),
        ("CreationTime", when(d.droid_created)),
        ("Hostname", d.hostname.clone()),
        ("MacAddress", d.mac.clone()),
        ("InteractionCount", d.access_count.unwrap_or(0).to_string()),
        (
            "PinStatus",
            if d.pin.is_some() { "True" } else { "False" }.to_owned(),
        ),
        ("FileDroid", bare(&d.file_droid)),
        ("VolumeDroid", bare(&d.volume_droid)),
        ("FileBirthDroid", bare(&d.file_birth_droid)),
        ("VolumeBirthDroid", bare(&d.volume_birth_droid)),
    ]
}

#[test]
fn automatic_matches_the_oracle() {
    let mut by_file = oracle("jumplist.csv");
    let mut checked = 0;
    for file in FILES {
        let data = fs::read(fixtures().join("jumplist").join(file)).unwrap();
        let list = jumplist::automatic(&data).unwrap();
        assert!(list.problems.is_empty(), "{file}: {:?}", list.problems);
        let rows = by_file.remove(file).unwrap_or_default();
        assert_eq!(list.destinations.len(), rows.len(), "{file}");
        for row in rows {
            // The oracle numbers entries most recent first, which is stream order.
            let at = format!("{file} MRU {}", row["MRU"]);
            let d = &list.destinations[row["MRU"].parse::<usize>().unwrap()];
            for (column, value) in columns(d, list.version) {
                assert_eq!(&value, &row[column], "{at}: {column}");
            }
            // The oracle appends what it resolves the path to (`… ==> …`).
            let path = row["Path"].split(" ==> ").next().unwrap();
            assert_eq!(d.path, path, "{at}: Path");
            check_link(d.link.as_ref().unwrap(), &row, &at);
            checked += 1;
        }
    }
    assert!(by_file.is_empty(), "files not tested: {:?}", by_file.keys());
    assert_eq!(checked, 31);
}

#[test]
fn custom_matches_the_oracle() {
    let mut by_file = oracle("jumplist-custom.csv");
    let mut checked = 0;
    for file in CUSTOM {
        let list = jumplist::custom(&fs::read(fixtures().join("jumplist").join(file)).unwrap());
        assert!(list.problems.is_empty(), "{file}: {:?}", list.problems);
        let links: Vec<(&Kind, &Link)> = list
            .categories
            .iter()
            .flat_map(|c| c.links.iter().map(move |l| (&c.kind, l)))
            .collect();
        let rows = by_file.remove(file).unwrap();
        assert_eq!(links.len(), rows.len(), "{file}");
        for (i, (row, (kind, link))) in rows.iter().zip(links).enumerate() {
            let at = format!("{file} link {i}");
            if !row["EntryName"].is_empty() {
                assert_eq!(kind, &Kind::Custom(row["EntryName"].clone()), "{at}");
            }
            check_link(link, row, &at);
            checked += 1;
        }
    }
    assert!(by_file.is_empty(), "files not tested: {:?}", by_file.keys());
    assert_eq!(checked, 17);
}

#[test]
fn custom_categories() {
    let kinds = |file: &str| -> Vec<(Kind, usize)> {
        let data = fs::read(fixtures().join("jumplist").join(file)).unwrap();
        jumplist::custom(&data)
            .categories
            .into_iter()
            .map(|c| (c.kind, c.links.len()))
            .collect()
    };
    let named = |name: &str| Kind::Custom(name.to_owned());
    assert_eq!(
        kinds(CUSTOM[0]),
        [
            (named("My Category 1"), 1),
            (Kind::Known(1), 0),
            (Kind::Tasks, 1),
            (named("My Category 2"), 1),
            (Kind::Known(2), 0),
        ]
    );
    assert_eq!(kinds(CUSTOM[1]), [(Kind::Tasks, 9)]);
    assert_eq!(
        kinds(CUSTOM[2]),
        [
            (named("Most visited"), 2),
            (named("Recently closed"), 1),
            (Kind::Tasks, 2),
        ]
    );
    // An empty list: a header and no categories.
    let empty =
        fs::read(fixtures().join("jumplist/plaso/c98dce577f884ef8.customDestinations-ms")).unwrap();
    let empty = jumplist::custom(&empty);
    assert!(empty.categories.is_empty() && empty.problems.is_empty());
}

mod garbage {
    use proptest::prelude::*;

    fn damaged(file: &str, flips: Vec<(usize, u8)>, cut: usize) -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/jumplist/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut data = std::fs::read(path).unwrap();
        for (at, byte) in flips {
            let len = data.len();
            data[at % len] = byte;
        }
        data.truncate(cut % (data.len() + 1));
        data
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_000))]

        /// A real jump list corrupted anywhere (its compound file tables,
        /// directory, `DestList` or links), or truncated: parsed or
        /// refused, never a panic.
        #[test]
        fn damaged_automatic_lists_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40), cut in any::<usize>()) {
            let data = damaged("Win10/f01b4d95cf55d32a.automaticDestinations-ms", flips, cut);
            if let Ok(file) = shell::compound::CompoundFile::parse(&data) {
                for entry in &file.entries {
                    let _ = file.stream(&entry.name);
                }
            }
            let _ = shell::jumplist::automatic(&data);
        }

        #[test]
        fn damaged_custom_lists_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40), cut in any::<usize>()) {
            let data = damaged("plaso/368d807282ccde9d.customDestinations-ms", flips, cut);
            let _ = shell::jumplist::custom(&data);
        }

        /// Any bytes at all.
        #[test]
        fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = shell::jumplist::automatic(&data);
            let _ = shell::jumplist::custom(&data);
        }
    }
}

/// Header counts far beyond the file: refused or read within bounds, not
/// allocated.
#[test]
fn huge_header_counts_are_bounded() {
    let mut data =
        fs::read(fixtures().join("jumplist/Win7/1b4dd67f29cb1962.automaticDestinations-ms"))
            .unwrap();
    for at in [44, 72] {
        data[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    }
    let _ = jumplist::automatic(&data);
    let mut custom =
        fs::read(fixtures().join("jumplist/plaso/368d807282ccde9d.customDestinations-ms")).unwrap();
    custom[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(jumplist::custom(&custom).categories.len(), 5);
}

/// A compound file (version 3, 512-byte sectors) holding `streams` in
/// regular sectors (each at least 4,096 bytes, so none is in the mini
/// stream), every entry a right sibling of the one before.
fn compound_file(streams: &[(&str, Vec<u8>)]) -> Vec<u8> {
    const SECTOR: usize = 512;
    const END: u32 = 0xffff_fffe;
    const FREE: u32 = 0xffff_ffff;
    let data: Vec<usize> = streams
        .iter()
        .map(|(_, b)| b.len().div_ceil(SECTOR))
        .collect();
    let dir = (streams.len() + 1).div_ceil(4);
    let fat_sectors = 1;
    let mut fat = vec![FREE; SECTOR / 4];
    fat[0] = 0xffff_fffd; // the FAT itself
    let mut next = fat_sectors;
    let mut chain = |n: usize, next: &mut usize| {
        let start = *next;
        for i in 0..n {
            fat[start + i] = if i + 1 == n {
                END
            } else {
                (start + i + 1) as u32
            };
        }
        *next += n;
        start as u32
    };
    let dir_start = chain(dir, &mut next);
    let starts: Vec<u32> = data.iter().map(|&n| chain(n, &mut next)).collect();
    assert!(next <= SECTOR / 4);
    let entry = |name: &str, kind: u8, right: u32, child: u32, start: u32, size: u32| {
        let mut e = vec![0u8; 128];
        let units: Vec<u16> = name.encode_utf16().chain([0]).collect();
        for (i, u) in units.iter().enumerate() {
            e[2 * i..2 * i + 2].copy_from_slice(&u.to_le_bytes());
        }
        e[64..66].copy_from_slice(&((units.len() * 2) as u16).to_le_bytes());
        e[66] = kind;
        e[67] = 1; // black
        e[68..72].copy_from_slice(&FREE.to_le_bytes()); // no left sibling
        e[72..76].copy_from_slice(&right.to_le_bytes());
        e[76..80].copy_from_slice(&child.to_le_bytes());
        e[116..120].copy_from_slice(&start.to_le_bytes());
        e[120..124].copy_from_slice(&size.to_le_bytes());
        e
    };
    let mut header = vec![0u8; SECTOR];
    header[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    header[24..26].copy_from_slice(&0x3eu16.to_le_bytes());
    header[26..28].copy_from_slice(&3u16.to_le_bytes());
    header[28..30].copy_from_slice(&0xfffeu16.to_le_bytes());
    header[30..32].copy_from_slice(&9u16.to_le_bytes());
    header[32..34].copy_from_slice(&6u16.to_le_bytes());
    header[44..48].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
    header[48..52].copy_from_slice(&dir_start.to_le_bytes());
    header[56..60].copy_from_slice(&4096u32.to_le_bytes());
    header[60..64].copy_from_slice(&END.to_le_bytes());
    header[68..72].copy_from_slice(&END.to_le_bytes());
    for i in 0..109 {
        let v = if i < fat_sectors { i as u32 } else { FREE };
        header[76 + 4 * i..80 + 4 * i].copy_from_slice(&v.to_le_bytes());
    }
    let mut out = header;
    for v in &fat {
        out.extend_from_slice(&v.to_le_bytes());
    }
    let mut directory = entry("Root Entry", 5, FREE, 1, END, 0);
    for (k, (name, bytes)) in streams.iter().enumerate() {
        let right = if k + 1 < streams.len() {
            (k + 2) as u32
        } else {
            FREE
        };
        directory.extend(entry(name, 2, right, FREE, starts[k], bytes.len() as u32));
    }
    directory.resize(dir * SECTOR, 0);
    out.extend(directory);
    for (_, bytes) in streams {
        let mut b = bytes.clone();
        b.resize(b.len().div_ceil(SECTOR) * SECTOR, 0);
        out.extend(b);
    }
    out
}

#[test]
fn destlist_entries_repeating_a_stream_read_it_once() {
    // A DestList (version 4) of 200 entries all naming stream "1": the link
    // is read for the first, and each repeat is a problem, not a copy.
    let link = std::fs::read(fixtures().join("lnk/Win10/services.lnk")).unwrap();
    let mut stream = link.clone();
    stream.resize(4096, 0);
    let entries = 200;
    let mut dest = vec![0u8; 32];
    dest[..4].copy_from_slice(&4u32.to_le_bytes());
    dest[4..8].copy_from_slice(&(entries as u32).to_le_bytes());
    for _ in 0..entries {
        let mut e = vec![0u8; 130];
        e[88..92].copy_from_slice(&1u32.to_le_bytes()); // entry number: stream "1"
        e[108..112].copy_from_slice(&u32::MAX.to_le_bytes()); // not pinned
        e[128..130].copy_from_slice(&1u16.to_le_bytes()); // a 1-character path
        e.extend_from_slice(&u16::from(b'x').to_le_bytes());
        e.extend_from_slice(&[0; 4]); // trailer
        dest.extend(e);
    }
    dest.resize(dest.len().max(4096), 0);
    let file = compound_file(&[("DestList", dest), ("1", stream)]);
    let list = jumplist::automatic(&file).unwrap();
    assert_eq!(list.destinations.len(), entries);
    let with_link = list
        .destinations
        .iter()
        .filter(|d| d.link.is_some())
        .count();
    assert_eq!(with_link, 1);
    let repeats = list
        .problems
        .iter()
        .filter(|p| p.contains("repeats stream 1"))
        .count();
    assert_eq!(repeats, entries - 1, "{:?}", list.problems.first());
}
