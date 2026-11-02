// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Cyber Experts
//
// This file is changed from Sootmark/shell (https://github.com/Sootmark/shell), whose code is under
// the MIT License or the Apache License 2.0 (LICENSE-MIT, LICENSE-APACHE).
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Shell items built here, for kinds the test sets hold too few of.

use shell::item::{Kind, decode};

/// A property storage (`1SPS`) of `System.ItemNameDisplay` (FMTID
/// `{B725F130-…}`, id 10) holding `name`.
fn display_name_store(name: &str) -> Vec<u8> {
    let text: Vec<u8> = name
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut value = Vec::new();
    value.extend_from_slice(&0u32.to_le_bytes()); // size, patched below
    value.extend_from_slice(&10u32.to_le_bytes()); // id
    value.push(0); // reserved
    value.extend_from_slice(&0x1fu16.to_le_bytes()); // VT_LPWSTR
    value.extend_from_slice(&0u16.to_le_bytes()); // padding
    value.extend_from_slice(&((text.len() / 2) as u32).to_le_bytes());
    value.extend_from_slice(&text);
    let len = value.len() as u32;
    value[..4].copy_from_slice(&len.to_le_bytes());
    let fmtid = [
        0x30, 0xf1, 0x25, 0xb7, 0xef, 0x47, 0x1a, 0x10, 0xa5, 0xf1, 0x02, 0x60, 0x8c, 0x9e, 0xeb,
        0xac,
    ];
    let mut storage = vec![0; 4];
    storage.extend_from_slice(b"1SPS");
    storage.extend_from_slice(&fmtid);
    storage.extend_from_slice(&value);
    storage.extend_from_slice(&0u32.to_le_bytes()); // no more values
    let len = storage.len() as u32;
    storage[..4].copy_from_slice(&len.to_le_bytes());
    storage
}

#[test]
fn an_app_under_applications_is_named_from_its_properties() {
    // Class 0x00, `APPS` at offset 6, the property store after it.
    let mut item = vec![0, 0, 0x00, 0x00, 0, 0];
    item.extend_from_slice(b"APPS");
    item.extend_from_slice(&display_name_store("Settings"));
    item.extend_from_slice(&[0; 8]);
    let len = item.len() as u16;
    item[..2].copy_from_slice(&len.to_le_bytes());
    let decoded = decode(&item);
    assert_eq!(decoded.kind, Kind::PropertyView);
    assert_eq!(decoded.name, "Settings");
}

#[test]
fn a_damaged_storage_size_does_not_stop_the_search() {
    // A size that runs past the store in front of the only signature: the
    // search for the next storage used to find the same one again, forever.
    let mut store = display_name_store("Calculator");
    store[..4].copy_from_slice(&0x0084_ffffu32.to_le_bytes());
    let mut item = vec![0, 0, 0x00, 0x00, 0, 0];
    item.extend_from_slice(b"APPS");
    item.extend_from_slice(&store);
    let len = item.len() as u16;
    item[..2].copy_from_slice(&len.to_le_bytes());
    let decoded = decode(&item);
    assert_eq!(decoded.kind, Kind::PropertyView);
    assert_eq!(decoded.name, "");

    // and a good storage after a damaged one is still found
    let mut two = display_name_store("Damaged");
    two[..4].copy_from_slice(&0x0084_ffffu32.to_le_bytes());
    two.extend_from_slice(&display_name_store("Notepad"));
    let mut item = vec![0, 0, 0x00, 0x00, 0, 0];
    item.extend_from_slice(b"APPS");
    item.extend_from_slice(&two);
    let len = item.len() as u16;
    item[..2].copy_from_slice(&len.to_le_bytes());
    assert_eq!(decode(&item).name, "Notepad");
}

#[test]
fn an_unterminated_unicode_short_name_ends_at_the_extension_block() {
    // A Windows XP folder (class 0x35: a directory with a Unicode name)
    // from the LNK test set: the short name "Échantill" runs into
    // the BEEF0004 block, whose long name is the folder's.
    let item = hex(concat!(
        "62003500000000001431180a1100c9006300680061006e00740069006c006c00",
        "420003000400efbe14310a0a1331006014000000c9006300680061006e007400",
        "69006c006c006f006e00730020006400270069006d0061006700650073000000",
        "2000"
    ));
    let decoded = decode(&item);
    assert_eq!(decoded.kind, Kind::Directory);
    assert_eq!(decoded.name, "Échantillons d'images");
    assert_eq!(decoded.extension_blocks, 1);
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn nested_delegate_items_are_bounded() {
    // A delegate (0x74, `CFSF`) wrapping a delegate, 6,000 deep: decoded
    // without recursing that deep.
    let mut item = vec![0, 0, 0x32, 0];
    for _ in 0..6000 {
        let mut outer = vec![0, 0, 0x74, 0, 0, 0];
        outer.extend_from_slice(b"CFSF");
        outer.extend_from_slice(&item);
        let len = outer.len() as u16;
        outer[..2].copy_from_slice(&len.to_le_bytes());
        item = outer;
        if item.len() > 60_000 {
            break;
        }
    }
    let decoded = decode(&item);
    assert_eq!(decoded.kind, Kind::UsersFilesFolder);
}

#[test]
fn an_item_staged_for_burning_is_named_from_its_file_entry() {
    // `D:\autorun.inf` in a Windows 10 jump list (jumplist_parser's
    // 5f7b5f1e01b83767): four 16-bit values, then the file's entry (class
    // 0x32, its long name in a BEEF0004 block), then a separator.
    let item = hex(concat!(
        "780000004175674d04000000010000000000010062003200640000007e506bb7",
        "01006175746f72756e2e696e6600480009000400efbe7e506bb7000000002e00",
        "0000080100000000000000000000000000000000000000000000000061007500",
        "74006f00720075006e002e0069006e00660000001a000000",
    ));
    let decoded = decode(&item);
    assert_eq!(decoded.kind, Kind::CdBurn);
    assert_eq!(decoded.name, "autorun.inf");
    assert!(decoded.modified.is_some());
    assert!(decoded.created.is_some());
    assert_eq!(decoded.extension_blocks, 1);

    // A published sample (MIT):
    // a folder's entry twice, the second without times.
    let sample = hex(concat!(
        "0a0100004175674d02000000020000007200310000000000093550131100414e",
        "5449474f7e3200004c0003000400efbe09355013000000001400000041004e00",
        "5400490047004f004e0045002000430048004100520041004300540045005200",
        "5300200046004f004c0044004500520000002a000e0000000a00efbe00000000",
        "180000008400310000000000000000001000414e5449474f4e45204348415241",
        "435445525320464f4c44455200004c0003000400efbe00000000000000001400",
        "000041004e005400490047004f004e0045002000430048004100520041004300",
        "5400450052005300200046004f004c0044004500520000002a000e0000000a00",
        "efbe010000002a0000000000",
    ));
    let decoded = decode(&sample);
    assert_eq!(decoded.kind, Kind::CdBurn);
    assert_eq!(decoded.name, "ANTIGONE CHARACTERS FOLDER");
    assert_eq!(decoded.modified, None);

    // The values skipped by their count, whatever they hold; separators of
    // size 0 or 1.
    let rebuilt = |values: &[u16], separator: &[u8]| {
        let mut built = item[..8].to_vec();
        built.extend_from_slice(&(values.len() as u32).to_le_bytes());
        built.extend(values.iter().flat_map(|v| v.to_le_bytes()));
        built.extend_from_slice(separator);
        built.extend_from_slice(&item[20..]);
        let len = built.len() as u16;
        built[..2].copy_from_slice(&len.to_le_bytes());
        decode(&built).name
    };
    assert_eq!(rebuilt(&[0x0123], &[]), "autorun.inf");
    assert_eq!(rebuilt(&[], &[1, 0]), "autorun.inf");
    assert_eq!(rebuilt(&[7, 7, 7], &[0, 0, 1, 0]), "autorun.inf");

    // An entry without a name after it doesn't unname the item.
    let mut nameless = item.clone();
    nameless.extend_from_slice(&[4, 0, 0x32, 0]);
    let len = nameless.len() as u16;
    nameless[..2].copy_from_slice(&len.to_le_bytes());
    assert_eq!(decode(&nameless).name, "autorun.inf");

    // Damage: a count past the end, an entry cut short, nothing after the
    // signature.
    let mut huge = item.clone();
    huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode(&huge).name, "");
    assert_eq!(decode(&item[..60]).kind, Kind::CdBurn);
    assert_eq!(decode(&item[..8]).name, "");
}

#[test]
fn nested_burn_items_are_bounded() {
    // An `AugM` item wrapping an `AugM` item, as deep as 64 KiB allows.
    let mut item = vec![0, 0, 0x32, 0];
    loop {
        let mut outer = vec![0, 0, 0x00, 0];
        outer.extend_from_slice(b"AugM");
        outer.extend_from_slice(&0u32.to_le_bytes());
        outer.extend_from_slice(&item);
        if outer.len() > 0xffff {
            break;
        }
        let len = outer.len() as u16;
        outer[..2].copy_from_slice(&len.to_le_bytes());
        item = outer;
    }
    assert_eq!(decode(&item).kind, Kind::CdBurn);
}

/// A property storage of one value: `fmtid`, property `id`, and the typed
/// value (its type, padding, then the data).
fn storage(fmtid: [u8; 16], id: u32, typed: &[u8]) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&((9 + typed.len()) as u32).to_le_bytes());
    value.extend_from_slice(&id.to_le_bytes());
    value.push(0);
    value.extend_from_slice(typed);
    let mut storage = vec![0; 4];
    storage.extend_from_slice(b"1SPS");
    storage.extend_from_slice(&fmtid);
    storage.extend(value);
    storage.extend_from_slice(&0u32.to_le_bytes());
    let len = storage.len() as u32;
    storage[..4].copy_from_slice(&len.to_le_bytes());
    storage
}

#[test]
fn a_library_folder_has_its_folders_times_and_reference() {
    // A library's folder (class 0x00, 0x10141981 at offset 6): its name, and
    // its own path as an item list in property 32 of {28636AA6-…}, here the
    // items of the test set's WinVista "Sample Pictures" link, whose last
    // item is the folder (MFT entry 714).
    let link = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/lnk/WinVista/Sample Pictures.lnk"
    ))
    .unwrap();
    let size = usize::from(u16::from_le_bytes([link[76], link[77]]));
    let list = &link[78..78 + size];
    let folder = decode(shell::item::items(list).last().unwrap());
    assert_eq!(folder.mft, Some((714, 1)));
    let mut typed = vec![0x11, 0x10, 0, 0]; // VT_VECTOR | VT_UI1
    typed.extend_from_slice(&(list.len() as u32).to_le_bytes());
    typed.extend_from_slice(list);
    typed.resize(typed.len().div_ceil(4) * 4, 0);
    let delegate = [
        0xa6, 0x6a, 0x63, 0x28, 0x3d, 0x95, 0xd2, 0x11, 0xb5, 0xd6, 0x00, 0xc0, 0x4f, 0xd9, 0x18,
        0xd0,
    ];
    let mut item = vec![0, 0, 0x00, 0x00, 0, 0];
    item.extend_from_slice(&0x1014_1981u32.to_le_bytes());
    item.extend_from_slice(&display_name_store("Pictures"));
    item.extend_from_slice(&storage(delegate, 32, &typed));
    item.extend_from_slice(&[0; 8]);
    let len = item.len() as u16;
    item[..2].copy_from_slice(&len.to_le_bytes());
    let decoded = decode(&item);
    assert_eq!(decoded.kind, Kind::PropertyView);
    assert_eq!(decoded.name, "Pictures");
    assert_eq!(decoded.mft, Some((714, 1)));
    assert_eq!(
        (decoded.created, decoded.modified, decoded.accessed),
        (folder.created, folder.modified, folder.accessed)
    );
    assert!(decoded.created.is_some());

    // Two display names: the first, as before.
    let mut two = vec![0, 0, 0x00, 0x00, 0, 0];
    two.extend_from_slice(&0x1014_1981u32.to_le_bytes());
    two.extend_from_slice(&display_name_store("First"));
    two.extend_from_slice(&display_name_store("Second"));
    two.extend_from_slice(&[0; 8]);
    let len = two.len() as u16;
    two[..2].copy_from_slice(&len.to_le_bytes());
    assert_eq!(decode(&two).name, "First");

    // Another property 32, or none: no reference.
    let mut other = item.clone();
    let at = other
        .windows(4)
        .rposition(|w| w == 32u32.to_le_bytes())
        .unwrap();
    other[at] = 33;
    assert_eq!(decode(&other).mft, None);
    assert_eq!(decode(&other).name, "Pictures");
}

/// The class identifier delegate items end with, then a delegate folder's.
fn delegate(class: u8, inner: &[u8], folder: [u8; 16]) -> Vec<u8> {
    let mut item = vec![0, 0, class, 0];
    item.extend_from_slice(&(inner.len() as u16).to_le_bytes());
    item.extend_from_slice(inner);
    item.extend_from_slice(&[
        0x74, 0x1a, 0x59, 0x5e, 0x96, 0xdf, 0xd3, 0x48, 0x8d, 0x67, 0x17, 0x33, 0xbc, 0xee, 0x28,
        0xba,
    ]);
    item.extend_from_slice(&folder);
    let len = item.len() as u16;
    item[..2].copy_from_slice(&len.to_le_bytes());
    item
}

#[test]
fn a_removable_drive_is_its_volume() {
    // `D:` under the Removable Drives delegate folder, from regipy's
    // `UsrClass.dat` (MIT): a 0x1F item whose class identifier would be
    // nonsense, its volume item inside.
    let item = hex(
        "55001f002f0010b7a6f519002f443a5c00000000000000000000000000000000000000000000000000000000000000000000000000741a595e96dfd3488d671733bcee28ba772cfbf52f0e164aa3813e560c68bc83",
    );
    let decoded = decode(&item);
    assert_eq!(decoded.kind, Kind::Volume);
    assert_eq!(decoded.name, "D:");
    assert_eq!(
        decoded.guid.as_deref(),
        Some("{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}")
    );
}

#[test]
fn search_results_are_a_search_folder() {
    // The Search Folder delegate (a 0x1F item): a users property view
    // (signature 0x23A3DFD5) without a display name.
    let mut inner = 0x23a3_dfd5_u32.to_le_bytes().to_vec();
    inner.extend_from_slice(&[0; 8]);
    let item = delegate(
        0x1f,
        &inner,
        [
            0x67, 0x1b, 0x73, 0x04, 0x33, 0xd9, 0x0a, 0x45, 0x90, 0xe6, 0x4a, 0xcd, 0x2e, 0x94,
            0x08, 0xfe,
        ],
    );
    let decoded = decode(&item);
    assert_eq!(decoded.kind, Kind::PropertyView);
    assert_eq!(decoded.name, "Search Folder");
    assert_eq!(
        decoded.guid.as_deref(),
        Some("{04731B67-D933-450A-90E6-4ACD2E9408FE}")
    );
}

#[test]
fn a_portable_device_delegate_is_named_from_its_first_string() {
    // The Portable Devices delegate (a 0x2E item): two counted strings from
    // offset 40, the device's name first.
    let name = "Pixel 7";
    let mut inner = vec![0; 34];
    inner[24..28].copy_from_slice(&(name.encode_utf16().count() as u32 + 1).to_le_bytes());
    inner[28..32].copy_from_slice(&1u32.to_le_bytes());
    inner.extend(name.encode_utf16().chain([0, 0]).flat_map(u16::to_le_bytes));
    let item = delegate(
        0x2e,
        &inner,
        [
            0x3c, 0x6d, 0x78, 0x35, 0x75, 0xb0, 0xb9, 0x49, 0x88, 0xdd, 0x02, 0x98, 0x76, 0xe1,
            0x1c, 0x01,
        ],
    );
    let decoded = decode(&item);
    assert_eq!(decoded.kind, Kind::PortableDevice);
    assert_eq!(decoded.name, name);
}

#[test]
fn a_users_property_view_with_signature_3b93afbb_has_its_display_name() {
    // A computer under Computers and Devices, from Plaso's `NTUSER-WIN7.DAT`
    // (Apache-2.0): a 0x00 item whose property store names it.
    let item = hex(
        "b7000000b100bbaf933ba300040000000000450000003153505330f125b7ef471a10a5f102608c9eebac290000000a000000001f0000000b00000063006f006e00740072006f006c006c006500720000000000000000002d000000315350533aa4bddeb337834391e74498da2995ab1100000003000000001300000000000000000000002d000000315350537343e50abe43ad4f85e469dc8633986e110000000b000000000b000000ffff0000000000000000000000000000",
    );
    let decoded = decode(&item);
    assert_eq!(decoded.kind, Kind::PropertyView);
    assert_eq!(decoded.name, "controller");
}

/// A 0x00 item with `signature` at offset 6 and `name` (with its count of
/// characters, NUL included, at `size_at`) at `name_at`.
fn mtp(signature: u32, size_at: usize, name_at: usize, name: &str) -> Vec<u8> {
    let mut item = vec![0; name_at];
    item[2] = 0x00;
    item[6..10].copy_from_slice(&signature.to_le_bytes());
    item[size_at..size_at + 4]
        .copy_from_slice(&(name.encode_utf16().count() as u32 + 1).to_le_bytes());
    item.extend(name.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
    item.extend_from_slice(&[0; 20]);
    let len = item.len() as u16;
    item[..2].copy_from_slice(&len.to_le_bytes());
    item[4..6].copy_from_slice(&(len - 6).to_le_bytes());
    item
}

#[test]
fn portable_device_storages_and_folders_are_named() {
    let storage = decode(&mtp(0x1031_2005, 38, 54, "Internal shared storage"));
    assert_eq!(storage.kind, Kind::PortableDevice);
    assert_eq!(storage.name, "Internal shared storage");
    let folder = decode(&mtp(0x0719_2006, 62, 74, "DCIM"));
    assert_eq!(folder.kind, Kind::PortableDeviceFolder);
    assert_eq!(folder.name, "DCIM");
    // As an iPhone's storage writes it: the first name empty, the folder's
    // in the second, then its object identifier.
    let mut item = vec![0; 74];
    item[6..10].copy_from_slice(&0x0719_2006u32.to_le_bytes());
    for (at, n) in [(62, 1u32), (66, 5), (70, 3)] {
        item[at..at + 4].copy_from_slice(&n.to_le_bytes());
    }
    item.extend("\0DCIM\0{1}\0".encode_utf16().flat_map(u16::to_le_bytes));
    let len = item.len() as u16;
    item[..2].copy_from_slice(&len.to_le_bytes());
    assert_eq!(decode(&item).name, "DCIM");
    // A count past the item: no name, never a panic.
    let mut cut = mtp(0x0719_2006, 62, 74, "DCIM");
    cut[62..66].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode(&cut).name, "");
}

/// A compressed folder item: Windows 10's layout (the name's length at 84,
/// the name at 92) or Windows XP's (60, 68), with `class` as its third
/// byte.
fn zip_entry(class: u8, windows_10: bool, name: &str) -> Vec<u8> {
    let (size_at, at) = if windows_10 { (84, 92) } else { (60, 68) };
    let mut item = vec![0; at];
    item[2] = class;
    item[size_at..size_at + 4].copy_from_slice(&(name.encode_utf16().count() as u32).to_le_bytes());
    item.extend(name.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
    item.extend_from_slice(&[0; 6]);
    let len = item.len() as u16;
    item[..2].copy_from_slice(&len.to_le_bytes());
    item
}

#[test]
fn items_under_a_zip_file_are_compressed_folders() {
    use shell::item::{Item, decode_child};
    let archive = Item {
        class: 0x32,
        kind: Kind::File,
        name: "photos.ZIP".to_owned(),
        guid: None,
        modified: None,
        created: None,
        accessed: None,
        mft: None,
        extension_blocks: 0,
    };
    // A class byte that alone would make it a file entry.
    for windows_10 in [true, false] {
        let item = zip_entry(0x31, windows_10, "2024 trip");
        let entry = decode_child(&item, Some(&archive), 1252);
        assert_eq!(entry.kind, Kind::CompressedFolder);
        assert_eq!(entry.name, "2024 trip");
        let inner = decode_child(&zip_entry(0x12, windows_10, "day 1"), Some(&entry), 1252);
        assert_eq!(
            (inner.kind, inner.name.as_str()),
            (Kind::CompressedFolder, "day 1")
        );
        // Without the archive above it, the class byte says what it is.
        assert_ne!(decode_child(&item, None, 1252).kind, Kind::CompressedFolder);
    }
    // Not a compressed folder's layout: decoded by its class byte.
    let folder = Item {
        name: "notes.txt".to_owned(),
        ..archive.clone()
    };
    assert_ne!(
        decode_child(&zip_entry(0x31, true, "x"), Some(&folder), 1252).kind,
        Kind::CompressedFolder
    );
    let garbage = [8u8, 0, 0x31, 0, 0xff, 0xff, 0xff, 0xff];
    assert_ne!(
        decode_child(&garbage, Some(&archive), 1252).kind,
        Kind::CompressedFolder
    );
}

mod damaged {
    use super::{delegate, mtp, zip_entry};
    use proptest::prelude::*;
    use shell::item::{Kind, decode, decode_child};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Any bytes, and the new kinds of item with bytes changed: decoded as far as they
        /// go, never a panic.
        #[test]
        fn damaged_items_never_panic(
            pick in 0usize..7,
            flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..12),
            cut in any::<usize>(),
            random in proptest::collection::vec(any::<u8>(), 0..300)
        ) {
            let mut item = match pick {
                5 => super::ftp_uri("ftp.example.org"),
                6 => super::ftp_folder("pub"),
                0 => mtp(0x1031_2005, 38, 54, "storage"),
                1 => mtp(0x0719_2006, 62, 74, "folder"),
                2 => zip_entry(0x31, true, "entry"),
                3 => delegate(0x1f, &[0x10, 0xb7, 0xa6, 0xf5, 4, 0, 0x2f, b'E'], [0x77, 0x2c, 0xfb, 0xf5, 0x2f, 0x0e, 0x16, 0x4a, 0xa3, 0x81, 0x3e, 0x56, 0x0c, 0x68, 0xbc, 0x83]),
                _ => random,
            };
            for (at, byte) in flips {
                if !item.is_empty() {
                    let at = at % item.len();
                    item[at] = byte;
                }
            }
            item.truncate(cut % (item.len() + 1));
            let archive = shell::item::Item {
                class: 0x32,
                kind: Kind::File,
                name: "a.zip".to_owned(),
                guid: None,
                modified: None,
                created: None,
                accessed: None,
                mft: None,
                extension_blocks: 0,
            };
            let site = shell::item::Item {
                class: 0x61,
                kind: Kind::Uri,
                name: "ftp://example.org".to_owned(),
                ..archive.clone()
            };
            let _ = decode(&item);
            let _ = decode_child(&item, Some(&archive), 1252);
            let _ = decode_child(&item, Some(&site), 1252);
        }
    }
}

/// An `ftp` URI item with its data: the server, a user name and an empty
/// password (each padded to 4 bytes after its size), then the scheme.
fn ftp_uri(host: &str) -> Vec<u8> {
    let padded = |text: &str| {
        let mut b = text.as_bytes().to_vec();
        b.push(0);
        b.resize(b.len().next_multiple_of(4), 0);
        b
    };
    let mut data = Vec::new();
    data.extend_from_slice(&0x2703u32.to_le_bytes());
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&0x01d0_08cf_dc71_3229u64.to_le_bytes());
    data.extend_from_slice(&[0; 16]);
    data.extend_from_slice(&0x15u32.to_le_bytes());
    for field in [padded(host), padded("anonymous"), vec![0; 4]] {
        data.extend_from_slice(&(field.len() as u32).to_le_bytes());
        data.extend_from_slice(&field);
    }
    let mut item = vec![0, 0, 0x61, 0x03];
    item.extend_from_slice(&(data.len() as u16).to_le_bytes());
    item.extend_from_slice(&data);
    item.extend_from_slice(b"ftp\0\0\0");
    let len = item.len() as u16;
    item[..2].copy_from_slice(&len.to_le_bytes());
    item
}

/// A folder under an FTP item: its name in ASCII at offset 38 (padded to 4
/// bytes), then in UTF-16.
fn ftp_folder(name: &str) -> Vec<u8> {
    let mut item = vec![0; 38];
    item[6..8].copy_from_slice(&5u16.to_le_bytes());
    item[8..10].copy_from_slice(&3u16.to_le_bytes());
    item[10..14].copy_from_slice(&0x10u32.to_le_bytes());
    item[30..34].copy_from_slice(&0x755u32.to_le_bytes());
    let mut ascii = name.as_bytes().to_vec();
    ascii.push(0);
    ascii.resize(ascii.len().next_multiple_of(4), 0);
    item.extend_from_slice(&ascii);
    item.extend(name.encode_utf16().chain([0, 0]).flat_map(u16::to_le_bytes));
    let len = item.len() as u16;
    item[..2].copy_from_slice(&len.to_le_bytes());
    item
}

#[test]
fn ftp_sites_and_their_folders_are_named() {
    use shell::item::decode_child;
    let site = decode(&ftp_uri("ftp.example.org"));
    assert_eq!(site.kind, Kind::Uri);
    assert_eq!(site.name, "ftp://ftp.example.org");
    // Each folder name's length lands its UTF-16 copy on another padding.
    let mut parent = site;
    for name in ["debian", "dists", "Debian6.0.10", "contrib"] {
        let folder = decode_child(&ftp_folder(name), Some(&parent), 1252);
        assert_eq!(
            (folder.kind.clone(), folder.name.as_str()),
            (Kind::FtpFolder, name)
        );
        parent = folder;
    }
    // Under anything else, decoded by the class byte.
    assert_ne!(decode(&ftp_folder("debian")).kind, Kind::FtpFolder);
}
