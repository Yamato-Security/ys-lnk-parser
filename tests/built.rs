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
