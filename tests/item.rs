//! Shell items built here, for kinds the test sets hold too few of.

use shell::item::{decode, Kind};

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
    // from Eric Zimmerman's test set: the short name "Échantill" runs into
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

    // Eric Zimmerman's sample (ExtensionBlocks' ShellItemSamples.txt, MIT):
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
