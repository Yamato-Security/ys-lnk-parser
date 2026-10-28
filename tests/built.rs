//! Links built here, for cases the test sets hold too few of (or none):
//! damaged offsets, and fields the real links don't vary.

use shell::lnk;

/// A 76-byte header with these flags.
fn header(flags: u32) -> Vec<u8> {
    let mut h = vec![0; 76];
    h[..4].copy_from_slice(&0x4cu32.to_le_bytes());
    h[4..20].copy_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    h[20..24].copy_from_slice(&flags.to_le_bytes());
    h
}

/// LinkInfo with a volume and an ANSI local base path, and a common path
/// suffix offset of `suffix_offset`.
fn link_info(local: &str, suffix_offset: u32) -> Vec<u8> {
    let mut volume = Vec::new();
    volume.extend_from_slice(&0x11u32.to_le_bytes()); // size
    volume.extend_from_slice(&3u32.to_le_bytes()); // DRIVE_FIXED
    volume.extend_from_slice(&0x1234_abcdu32.to_le_bytes());
    volume.extend_from_slice(&0x10u32.to_le_bytes()); // label offset
    volume.push(0); // empty label
    let local_at = 0x1c + volume.len();
    let mut info = vec![0; 0x1c];
    info.extend_from_slice(&volume);
    info.extend_from_slice(local.as_bytes());
    info.push(0);
    let suffix_at = info.len();
    info.push(0); // empty suffix
    let size = info.len() as u32;
    info[..4].copy_from_slice(&size.to_le_bytes());
    info[4..8].copy_from_slice(&0x1cu32.to_le_bytes());
    info[8..12].copy_from_slice(&1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    info[12..16].copy_from_slice(&0x1cu32.to_le_bytes());
    info[16..20].copy_from_slice(&(local_at as u32).to_le_bytes());
    let suffix = if suffix_offset == u32::MAX {
        suffix_at as u32
    } else {
        suffix_offset
    };
    info[24..28].copy_from_slice(&suffix.to_le_bytes());
    info
}

#[test]
fn link_info_offsets_into_the_header_are_absent() {
    // A suffix offset of 0 points at the LinkInfo size, whose low byte was
    // read as the suffix (and appended to the local path).
    for suffix in [u32::MAX, 0, 4, 0x1b, 0xffff] {
        let mut data = header(0x2); // HasLinkInfo
        data.extend_from_slice(&link_info(r"E:\report.docx", suffix));
        data.extend_from_slice(&0u32.to_le_bytes()); // terminal block
        let link = lnk::parse(&data).unwrap();
        assert_eq!(link.local_path, r"E:\report.docx", "{suffix:#x}");
        assert_eq!(link.common_path, "", "{suffix:#x}");
        let volume = link.volume.unwrap();
        assert_eq!((volume.drive_type, volume.serial), (3, 0x1234_abcd));
    }
}

/// A GUID's 16 bytes as stored, from its text form.
fn guid(text: &str) -> [u8; 16] {
    let hex: String = text.chars().filter(char::is_ascii_hexdigit).collect();
    let b: Vec<u8> = (0..32)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let mut out = [0; 16];
    out[..4].copy_from_slice(&[b[3], b[2], b[1], b[0]]);
    out[4..6].copy_from_slice(&[b[5], b[4]]);
    out[6..8].copy_from_slice(&[b[7], b[6]]);
    out[8..].copy_from_slice(&b[8..]);
    out
}

/// A tracker data block: machine name, droid and birth droid.
fn tracker(machine: &str, droid: [&str; 2], birth: [&str; 2]) -> Vec<u8> {
    let mut block = Vec::new();
    block.extend_from_slice(&0x60u32.to_le_bytes());
    block.extend_from_slice(&0xa000_0003u32.to_le_bytes());
    block.extend_from_slice(&0x58u32.to_le_bytes());
    block.extend_from_slice(&0u32.to_le_bytes());
    let mut name = [0u8; 16];
    name[..machine.len()].copy_from_slice(machine.as_bytes());
    block.extend_from_slice(&name);
    for g in droid.iter().chain(&birth) {
        block.extend_from_slice(&guid(g));
    }
    block
}

#[test]
fn only_a_version_1_object_id_has_a_mac_address_and_time() {
    let link = |object: &str| {
        let mut data = header(0);
        let volume = "a3355a32-d86e-4920-adfd-dc842d90c45f";
        data.extend_from_slice(&tracker("pc01", [volume, object], [volume, object]));
        data.extend_from_slice(&0u32.to_le_bytes());
        lnk::parse(&data).unwrap().tracker.unwrap()
    };
    // version 1: 2010-06-21 14:55:12 on a4:ba:db:43:b0:4f
    let v1 = link("7396a013-7d44-11df-a3ad-a4badb43b04f");
    assert_eq!(v1.mac, "a4:ba:db:43:b0:4f");
    assert_ne!(v1.created, 0);
    // version 8 (lnk-forensic's crafted removable_media.lnk), and version 4
    for other in [
        "66666666-7777-8888-9999-aaaaaaaaaaaa",
        "9b2c3f60-1d34-4c3e-8a0a-3f5c2e1d9b7a",
    ] {
        let t = link(other);
        assert_eq!((t.mac.as_str(), t.created), ("", 0), "{other}");
        assert_eq!(t.object_id, format!("{{{}}}", other.to_uppercase()));
    }
}

fn block(signature: u32, body: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
    b.extend_from_slice(&signature.to_le_bytes());
    b.extend_from_slice(body);
    b
}

fn utf16z(text: &str, size: usize) -> Vec<u8> {
    let mut b: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    b.resize(size, 0);
    b
}

#[test]
fn header_fields_and_names() {
    let mut data = header(1 << 27 | 0x80); // IsUnicode, and an undefined bit
    data[56..60].copy_from_slice(&(-3i32).to_le_bytes()); // icon index
    data[60..64].copy_from_slice(&3u32.to_le_bytes()); // SW_SHOWMAXIMIZED
    data[64..66].copy_from_slice(&0x0650u16.to_le_bytes()); // Ctrl+Alt+P
    data.extend_from_slice(&0u32.to_le_bytes());
    let link = lnk::parse(&data).unwrap();
    assert_eq!(link.icon_index, -3);
    assert_eq!(link.show_command_name(), Some("SW_SHOWMAXIMIZED"));
    assert_eq!(link.hotkey_name(), "Ctrl+Alt+P");
    assert_eq!(link.unknown_flags(), 1 << 27);
    assert_eq!(link.flag_names(), ["IsUnicode"]);
    let mut other = link.clone();
    for (hotkey, name) in [
        (0, ""),
        (0x0170, "Shift+F1"),
        (0x0291, "Ctrl+ScrollLock"),
        (0x08ff, "0x08+0xFF"),
    ] {
        other.hotkey = hotkey;
        assert_eq!(other.hotkey_name(), name);
    }
    other.show_command = 2;
    assert_eq!(other.show_command_name(), None);
}

#[test]
fn shim_property_store_and_vista_blocks() {
    let mut data = header(0x80);
    data.extend(block(0xa000_0008, &utf16z("WINXPSP3", 0x80)));
    // a property store with System.Link.TargetParsingPath
    let fmtid = [
        0xfc, 0xb3, 0xb4, 0xb9, 0x51, 0x2b, 0x42, 0x4a, 0xb5, 0xd8, 0x32, 0x41, 0x46, 0xaf, 0xcf,
        0x25,
    ];
    let path = "C:\\Windows\\notepad.exe";
    let units: Vec<u16> = path.encode_utf16().chain([0]).collect();
    let mut typed = vec![0x1f, 0, 0, 0];
    typed.extend_from_slice(&(units.len() as u32).to_le_bytes());
    typed.extend(units.iter().flat_map(|u| u.to_le_bytes()));
    let mut value = Vec::new();
    value.extend_from_slice(&((9 + typed.len()) as u32).to_le_bytes());
    value.extend_from_slice(&2u32.to_le_bytes());
    value.push(0);
    value.extend(typed);
    let mut storage = vec![0; 4];
    storage.extend_from_slice(b"1SPS");
    storage.extend_from_slice(&fmtid);
    storage.extend(value);
    storage.extend_from_slice(&0u32.to_le_bytes());
    let n = storage.len() as u32;
    storage[..4].copy_from_slice(&n.to_le_bytes());
    storage.extend_from_slice(&0u32.to_le_bytes());
    data.extend(block(0xa000_0009, &storage));
    // a Vista ID list holding one drive item
    let mut list = vec![0x19, 0x00, 0x2f];
    list.extend_from_slice(b"C:\\");
    list.resize(0x19, 0);
    list.extend_from_slice(&[0, 0]);
    data.extend(block(0xa000_000c, &list));
    data.extend_from_slice(&0u32.to_le_bytes());
    let link = lnk::parse(&data).unwrap();
    assert_eq!(link.shim_layer, "WINXPSP3");
    assert_eq!(link.properties.len(), 1);
    assert_eq!(
        link.properties[0].canonical_name(),
        Some("System.Link.TargetParsingPath")
    );
    assert_eq!(link.properties[0].value.display(), path);
    assert_eq!(link.vista_target_path(), "C:");
    assert_eq!(link.blocks, [0xa000_0008, 0xa000_0009, 0xa000_000c]);
    assert!(link.problems.is_empty(), "{:?}", link.problems);
}

#[test]
fn damage_is_listed() {
    // the target list runs past the end
    let mut data = header(0x1);
    data.extend_from_slice(&500u16.to_le_bytes());
    let link = lnk::parse(&data).unwrap();
    assert!(
        link.problems[0].contains("target ID list"),
        "{:?}",
        link.problems
    );
    // an extra data block runs past the end
    let mut data = header(0);
    data.extend_from_slice(&block(0xa000_0003, &[0; 8])[..12]);
    data[76..80].copy_from_slice(&0x60u32.to_le_bytes());
    let link = lnk::parse(&data).unwrap();
    assert!(
        link.problems[0].contains("TrackerDataBlock"),
        "{:?}",
        link.problems
    );
    // no terminal block
    let link = lnk::parse(&header(0)).unwrap();
    assert_eq!(link.problems, ["the extra data has no terminal block"]);
    // the string data runs past the end and capping doesn't help
    let mut data = header(0x20); // HasArguments
    data.extend_from_slice(&40u16.to_le_bytes());
    data.extend_from_slice(b"abc");
    let link = lnk::parse(&data).unwrap();
    assert!(link.problems[0].starts_with("the string data runs past the end"));
}

#[cfg(feature = "codepages")]
#[test]
fn a_code_page_for_text_that_is_not_unicode() {
    // a Japanese system's link: the working directory in Shift-JIS
    let mut data = header(0x10); // HasWorkingDir
    let sjis = b"C:\\\x83\x66\x83\x58\x83\x4e\x83\x67\x83\x62\x83\x76";
    data.extend_from_slice(&(sjis.len() as u16).to_le_bytes());
    data.extend_from_slice(sjis);
    data.extend_from_slice(&0u32.to_le_bytes());
    let link = lnk::parse_with(&data, &lnk::Options { code_page: 932 }).unwrap();
    assert_eq!(link.working_dir, "C:\\デスクトップ");
    assert_eq!(lnk::parse(&data).unwrap().working_dir.chars().count(), 15);
}
