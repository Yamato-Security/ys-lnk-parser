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
