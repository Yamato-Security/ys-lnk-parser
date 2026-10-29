//! Shell link (`.lnk`) files, from Microsoft's MS-SHLLINK: what a shortcut
//! points at, with the target's times, size and attributes as they were
//! when the link was last saved, the volume and path it was on, and the
//! machine it was made on.
//!
//! The file is a 76-byte header, then (as its flags say) the target's
//! shell item list, the link information (volume, local and network
//! paths), string data (name, relative path, working directory, arguments,
//! icon) and extra data blocks (tracker, environment variables, known and
//! special folders, property store, console, Darwin, shim, …), every one
//! of which is decoded.

use core::fmt;

use crate::codepage;
use crate::item::{self, Item};
use crate::property::{self, Property};
use crate::{u16_at, u32_at, u64_at};

const HEADER_SIZE: u32 = 0x4c;
/// `{00021401-0000-0000-C000-000000000046}`.
pub(crate) const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
/// The most characters Windows reads of a link's name, relative path and
/// working directory (`MAX_PATH`).
const MAX_PATH: usize = 260;

/// Link flags (MS-SHLLINK 2.1.1), in bit order.
pub const FLAGS: [&str; 27] = [
    "HasLinkTargetIDList",
    "HasLinkInfo",
    "HasName",
    "HasRelativePath",
    "HasWorkingDir",
    "HasArguments",
    "HasIconLocation",
    "IsUnicode",
    "ForceNoLinkInfo",
    "HasExpString",
    "RunInSeparateProcess",
    "Unused1",
    "HasDarwinID",
    "RunAsUser",
    "HasExpIcon",
    "NoPidlAlias",
    "Unused2",
    "RunWithShimLayer",
    "ForceNoLinkTrack",
    "EnableTargetMetadata",
    "DisableLinkPathTracking",
    "DisableKnownFolderTracking",
    "DisableKnownFolderAlias",
    "AllowLinkToLink",
    "UnaliasOnSave",
    "PreferEnvironmentPath",
    "KeepLocalIDListForUNCTarget",
];

/// How a link is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// The code page text that isn't Unicode is in (the system's ANSI code
    /// page, which the link doesn't record): 1252 by default, 932 for a
    /// Japanese system (see [`codepage`]).
    pub code_page: u16,
}

impl Default for Options {
    fn default() -> Self {
        Self { code_page: 1252 }
    }
}

/// Why a file couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Byte offset where it went wrong.
    pub offset: usize,
    /// What went wrong.
    pub reason: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.reason, self.offset)
    }
}

impl std::error::Error for Error {}

fn error(offset: usize, reason: impl Into<String>) -> Error {
    Error {
        offset,
        reason: reason.into(),
    }
}

/// The volume a local target was on (MS-SHLLINK 2.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    /// `DRIVE_*`: 0 unknown, 1 no root, 2 removable, 3 fixed, 4 remote,
    /// 5 CD-ROM, 6 RAM disk.
    pub drive_type: u32,
    /// Its serial number.
    pub serial: u32,
    /// Its label.
    pub label: String,
}

/// The tracker data block (MS-SHLLINK 2.5.10): the machine the link was
/// made on, and the target's distributed link tracking identifiers, now
/// and when the target was first tracked ("birth").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracker {
    /// The NetBIOS name of the machine.
    pub machine_id: String,
    /// The volume's identifier.
    pub volume_id: String,
    /// The file's object identifier (a version 1 GUID: its node is a MAC
    /// address, its timestamp when it was made).
    pub object_id: String,
    /// The MAC address in the object identifier: `00:15:5d:01:6d:02`
    /// (empty when it isn't a version 1 GUID).
    pub mac: String,
    /// When the object identifier was made (FILETIME; 0 when it isn't a
    /// version 1 GUID).
    pub created: u64,
    /// The volume's identifier when the target was first tracked.
    pub birth_volume_id: String,
    /// The file's object identifier when the target was first tracked.
    pub birth_object_id: String,
    /// The MAC address in the birth object identifier.
    pub birth_mac: String,
    /// When the birth object identifier was made (FILETIME).
    pub birth_created: u64,
}

/// A console window's properties (ConsoleDataBlock, MS-SHLLINK 2.5.1):
/// the link starts a console application.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // the block's own flags
pub struct Console {
    /// Text colors (`FOREGROUND_*`, `BACKGROUND_*`).
    pub fill_attributes: u16,
    /// Popup text colors.
    pub popup_fill_attributes: u16,
    /// Screen buffer size, in characters (columns, rows).
    pub screen_buffer_size: (i16, i16),
    /// Window size, in characters.
    pub window_size: (i16, i16),
    /// Window origin, in pixels.
    pub window_origin: (i16, i16),
    /// Font size (raster fonts: width and height in the two halves).
    pub font_size: u32,
    /// Font family (`FF_*`, `TMPF_*`).
    pub font_family: u32,
    /// Font weight (400 normal, 700 bold).
    pub font_weight: u32,
    /// Font face name.
    pub face_name: String,
    /// Cursor size, as a percentage of a character cell.
    pub cursor_size: u32,
    /// Full screen.
    pub full_screen: bool,
    /// QuickEdit mode.
    pub quick_edit: bool,
    /// Insert mode.
    pub insert_mode: bool,
    /// The system positions the window.
    pub auto_position: bool,
    /// Lines of command history per buffer.
    pub history_buffer_size: u32,
    /// Number of command history buffers.
    pub history_buffers: u32,
    /// Duplicate history entries are discarded.
    pub history_no_dup: bool,
    /// The 16 console colors (`0x00BBGGRR`).
    pub color_table: [u32; 16],
}

/// A parsed link.
#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    /// How many bytes it occupies: through its terminal block, or all of
    /// the data when it's truncated (links follow one another in custom
    /// jump lists).
    pub length: usize,
    /// Link flags.
    pub flags: u32,
    /// The target's attributes (`FILE_ATTRIBUTE_*`).
    pub attributes: u32,
    /// The target's creation time (FILETIME; 0 when not recorded).
    pub created: u64,
    /// The target's last access time.
    pub accessed: u64,
    /// The target's last write time.
    pub modified: u64,
    /// The target's size (low 32 bits).
    pub size: u32,
    /// The icon's index within the icon location.
    pub icon_index: i32,
    /// How the target's window is shown (`SW_*`; see
    /// [`Link::show_command_name`]).
    pub show_command: u32,
    /// The keyboard shortcut (see [`Link::hotkey_name`]): 0 when none.
    pub hotkey: u16,
    /// The target's shell items, in order.
    pub target: Vec<Item>,
    /// The target's volume.
    pub volume: Option<Volume>,
    /// The target's local path.
    pub local_path: String,
    /// The target's network share (`\\server\share`).
    pub network_path: String,
    /// The drive the network share was mapped to (`Z:`).
    pub network_device: String,
    /// The network provider (`WNNC_NET_*`; see [`network_provider_name`]),
    /// when recorded.
    pub network_provider: Option<u32>,
    /// The path under the network share.
    pub common_path: String,
    /// String data, when present.
    pub name: String,
    /// The target relative to the link.
    pub relative_path: String,
    /// The working directory.
    pub working_dir: String,
    /// Command line arguments.
    pub arguments: String,
    /// Icon location.
    pub icon_location: String,
    /// The target from the environment variables block (`%windir%\…`).
    pub environment_target: String,
    /// The icon location from the icon environment block.
    pub icon_environment_target: String,
    /// The Windows Installer (Darwin) application identifier.
    pub darwin_id: String,
    /// The shim layer the target runs under (`WINXPSP3`, …).
    pub shim_layer: String,
    /// The known folder the target is in (its GUID; see
    /// [`crate::guid_names`]) and the offset of its shell item in the
    /// target list.
    pub known_folder: Option<(String, u32)>,
    /// The special folder the target is in (a `CSIDL`; see
    /// [`special_folder_name`]) and the offset of its shell item.
    pub special_folder: Option<(u32, u32)>,
    /// Console window properties, for a console application.
    pub console: Option<Console>,
    /// The console's code page (ConsoleFEDataBlock).
    pub console_code_page: Option<u32>,
    /// The property store block's properties.
    pub properties: Vec<Property>,
    /// The target's shell items from the VistaAndAboveIDList block (which
    /// Windows uses instead of the target list when present).
    pub vista_target: Vec<Item>,
    /// The tracker block.
    pub tracker: Option<Tracker>,
    /// Extra data blocks present, by signature, in order.
    pub blocks: Vec<u32>,
    /// What's damaged or unusual about the file, in order met (the parse
    /// goes on where it can).
    pub problems: Vec<String>,
}

impl Link {
    /// The flag names set, in bit order.
    #[must_use]
    pub fn flag_names(&self) -> Vec<&'static str> {
        FLAGS
            .iter()
            .enumerate()
            .filter(|(bit, _)| self.flags & (1 << bit) != 0)
            .map(|(_, name)| *name)
            .collect()
    }

    /// Flag bits set that MS-SHLLINK doesn't define.
    #[must_use]
    pub fn unknown_flags(&self) -> u32 {
        self.flags & !((1 << FLAGS.len()) - 1)
    }

    /// The target's shell items as a path: `This PC\C:\Windows\notepad.exe`.
    /// A network item's leading backslashes are dropped after the first
    /// item (`Network\server\share`).
    #[must_use]
    pub fn target_path(&self) -> String {
        path(&self.target)
    }

    /// The VistaAndAboveIDList target as a path.
    #[must_use]
    pub fn vista_target_path(&self) -> String {
        path(&self.vista_target)
    }

    /// `SW_SHOWNORMAL`, `SW_SHOWMAXIMIZED` or `SW_SHOWMINNOACTIVE`; `None`
    /// for any other value (which Windows takes as `SW_SHOWNORMAL`).
    #[must_use]
    pub fn show_command_name(&self) -> Option<&'static str> {
        match self.show_command {
            1 => Some("SW_SHOWNORMAL"),
            3 => Some("SW_SHOWMAXIMIZED"),
            7 => Some("SW_SHOWMINNOACTIVE"),
            _ => None,
        }
    }

    /// The keyboard shortcut: `Ctrl+Alt+P`, `Shift+F5`; empty when none.
    #[must_use]
    pub fn hotkey_name(&self) -> String {
        if self.hotkey == 0 {
            return String::new();
        }
        let [key, modifiers] = self.hotkey.to_le_bytes();
        let mut parts: Vec<String> = [(0x02, "Ctrl"), (0x01, "Shift"), (0x04, "Alt")]
            .iter()
            .filter(|(bit, _)| modifiers & bit != 0)
            .map(|(_, name)| (*name).to_owned())
            .collect();
        if modifiers & !0x07 != 0 {
            parts.push(format!("0x{:02X}", modifiers & !0x07));
        }
        parts.push(match key {
            0x30..=0x39 | 0x41..=0x5a => char::from(key).to_string(),
            0x70..=0x87 => format!("F{}", key - 0x6f),
            0x90 => "NumLock".to_owned(),
            0x91 => "ScrollLock".to_owned(),
            other => format!("0x{other:02X}"),
        });
        parts.join("+")
    }

    fn has(&self, bit: u32) -> bool {
        self.flags & (1 << bit) != 0
    }
}

fn path(items: &[Item]) -> String {
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            if i > 0 {
                item.name.trim_start_matches('\\')
            } else {
                item.name.as_str()
            }
        })
        .collect::<Vec<_>>()
        .join("\\")
}

/// Extra data block names (MS-SHLLINK 2.5), by signature.
#[must_use]
pub const fn block_name(signature: u32) -> &'static str {
    match signature {
        0xa000_0001 => "EnvironmentVariableDataBlock",
        0xa000_0002 => "ConsoleDataBlock",
        0xa000_0003 => "TrackerDataBlock",
        0xa000_0004 => "ConsoleFEDataBlock",
        0xa000_0005 => "SpecialFolderDataBlock",
        0xa000_0006 => "DarwinDataBlock",
        0xa000_0007 => "IconEnvironmentDataBlock",
        0xa000_0008 => "ShimDataBlock",
        0xa000_0009 => "PropertyStoreDataBlock",
        0xa000_000b => "KnownFolderDataBlock",
        0xa000_000c => "VistaAndAboveIDListDataBlock",
        _ => "Unknown",
    }
}

/// A special folder's `CSIDL` name (Windows SDK `shlobj.h`).
#[must_use]
pub const fn special_folder_name(csidl: u32) -> Option<&'static str> {
    Some(match csidl {
        0x00 => "CSIDL_DESKTOP",
        0x01 => "CSIDL_INTERNET",
        0x02 => "CSIDL_PROGRAMS",
        0x03 => "CSIDL_CONTROLS",
        0x04 => "CSIDL_PRINTERS",
        0x05 => "CSIDL_PERSONAL",
        0x06 => "CSIDL_FAVORITES",
        0x07 => "CSIDL_STARTUP",
        0x08 => "CSIDL_RECENT",
        0x09 => "CSIDL_SENDTO",
        0x0a => "CSIDL_BITBUCKET",
        0x0b => "CSIDL_STARTMENU",
        0x0d => "CSIDL_MYMUSIC",
        0x0e => "CSIDL_MYVIDEO",
        0x10 => "CSIDL_DESKTOPDIRECTORY",
        0x11 => "CSIDL_DRIVES",
        0x12 => "CSIDL_NETWORK",
        0x13 => "CSIDL_NETHOOD",
        0x14 => "CSIDL_FONTS",
        0x15 => "CSIDL_TEMPLATES",
        0x16 => "CSIDL_COMMON_STARTMENU",
        0x17 => "CSIDL_COMMON_PROGRAMS",
        0x18 => "CSIDL_COMMON_STARTUP",
        0x19 => "CSIDL_COMMON_DESKTOPDIRECTORY",
        0x1a => "CSIDL_APPDATA",
        0x1b => "CSIDL_PRINTHOOD",
        0x1c => "CSIDL_LOCAL_APPDATA",
        0x1d => "CSIDL_ALTSTARTUP",
        0x1e => "CSIDL_COMMON_ALTSTARTUP",
        0x1f => "CSIDL_COMMON_FAVORITES",
        0x20 => "CSIDL_INTERNET_CACHE",
        0x21 => "CSIDL_COOKIES",
        0x22 => "CSIDL_HISTORY",
        0x23 => "CSIDL_COMMON_APPDATA",
        0x24 => "CSIDL_WINDOWS",
        0x25 => "CSIDL_SYSTEM",
        0x26 => "CSIDL_PROGRAM_FILES",
        0x27 => "CSIDL_MYPICTURES",
        0x28 => "CSIDL_PROFILE",
        0x29 => "CSIDL_SYSTEMX86",
        0x2a => "CSIDL_PROGRAM_FILESX86",
        0x2b => "CSIDL_PROGRAM_FILES_COMMON",
        0x2c => "CSIDL_PROGRAM_FILES_COMMONX86",
        0x2d => "CSIDL_COMMON_TEMPLATES",
        0x2e => "CSIDL_COMMON_DOCUMENTS",
        0x2f => "CSIDL_COMMON_ADMINTOOLS",
        0x30 => "CSIDL_ADMINTOOLS",
        0x31 => "CSIDL_CONNECTIONS",
        0x35 => "CSIDL_COMMON_MUSIC",
        0x36 => "CSIDL_COMMON_PICTURES",
        0x37 => "CSIDL_COMMON_VIDEO",
        0x38 => "CSIDL_RESOURCES",
        0x39 => "CSIDL_RESOURCES_LOCALIZED",
        0x3a => "CSIDL_COMMON_OEM_LINKS",
        0x3b => "CSIDL_CDBURN_AREA",
        0x3d => "CSIDL_COMPUTERSNEARME",
        _ => return None,
    })
}

/// A network provider's name (`WNNC_NET_*`, MS-SHLLINK 2.3.2).
#[must_use]
pub const fn network_provider_name(provider: u32) -> Option<&'static str> {
    Some(match provider {
        0x001a_0000 => "WNNC_NET_AVID",
        0x001b_0000 => "WNNC_NET_DOCUSPACE",
        0x001c_0000 => "WNNC_NET_MANGOSOFT",
        0x001d_0000 => "WNNC_NET_SERNET",
        0x001e_0000 => "WNNC_NET_RIVERFRONT1",
        0x001f_0000 => "WNNC_NET_RIVERFRONT2",
        0x0020_0000 => "WNNC_NET_DECORB",
        0x0021_0000 => "WNNC_NET_PROTSTOR",
        0x0022_0000 => "WNNC_NET_FJ_REDIR",
        0x0023_0000 => "WNNC_NET_DISTINCT",
        0x0024_0000 => "WNNC_NET_TWINS",
        0x0025_0000 => "WNNC_NET_RDR2SAMPLE",
        0x0026_0000 => "WNNC_NET_CSC",
        0x0027_0000 => "WNNC_NET_3IN1",
        0x0029_0000 => "WNNC_NET_EXTENDNET",
        0x002a_0000 => "WNNC_NET_STAC",
        0x002b_0000 => "WNNC_NET_FOXBAT",
        0x002c_0000 => "WNNC_NET_YAHOO",
        0x002d_0000 => "WNNC_NET_EXIFS",
        0x002e_0000 => "WNNC_NET_DAV",
        0x002f_0000 => "WNNC_NET_KNOWARE",
        0x0030_0000 => "WNNC_NET_OBJECT_DIRE",
        0x0031_0000 => "WNNC_NET_MASFAX",
        0x0032_0000 => "WNNC_NET_HOB_NFS",
        0x0033_0000 => "WNNC_NET_SHIVA",
        0x0034_0000 => "WNNC_NET_IBMAL",
        0x0035_0000 => "WNNC_NET_LOCK",
        0x0036_0000 => "WNNC_NET_TERMSRV",
        0x0037_0000 => "WNNC_NET_SRT",
        0x0038_0000 => "WNNC_NET_QUINCY",
        0x0039_0000 => "WNNC_NET_OPENAFS",
        0x003a_0000 => "WNNC_NET_AVID1",
        0x003b_0000 => "WNNC_NET_DFS",
        0x003c_0000 => "WNNC_NET_KWNP",
        0x003d_0000 => "WNNC_NET_ZENWORKS",
        0x003e_0000 => "WNNC_NET_DRIVEONWEB",
        0x003f_0000 => "WNNC_NET_VMWARE",
        0x0040_0000 => "WNNC_NET_RSFX",
        0x0041_0000 => "WNNC_NET_MFILES",
        0x0042_0000 => "WNNC_NET_MS_NFS",
        0x0043_0000 => "WNNC_NET_GOOGLE",
        0x0002_0000 => "WNNC_NET_LANMAN",
        _ => return None,
    })
}

/// A NUL-terminated string at `at` in `data`, UTF-16 or code page.
fn string_at(data: &[u8], at: usize, unicode: bool, code_page: u16) -> String {
    let rest = data.get(at..).unwrap_or_default();
    if unicode {
        utf16(rest)
    } else {
        codepage::decode(rest, code_page)
    }
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Parse a link, reading text that isn't Unicode as Windows-1252.
///
/// # Errors
/// When it isn't a shell link (wrong header size or class identifier) or
/// its header is truncated. Damaged later sections end the parse there,
/// keeping what came before, and are listed in [`Link::problems`].
pub fn parse(data: &[u8]) -> Result<Link, Error> {
    parse_with(data, &Options::default())
}

/// Parse a link with `options` (the code page of text that isn't Unicode).
///
/// # Errors
/// As [`parse`].
pub fn parse_with(data: &[u8], options: &Options) -> Result<Link, Error> {
    if u32_at(data, 0) != Some(HEADER_SIZE) || data.get(4..20) != Some(&LINK_CLSID[..]) {
        return Err(error(0, "not a shell link (no LNK header)"));
    }
    let field = |at| u32_at(data, at).ok_or_else(|| error(at, "header truncated"));
    let time = |at| u64_at(data, at).ok_or_else(|| error(at, "header truncated"));
    let code_page = options.code_page;
    let mut link = Link {
        length: data.len(),
        flags: field(20)?,
        attributes: field(24)?,
        created: time(28)?,
        accessed: time(36)?,
        modified: time(44)?,
        size: field(52)?,
        icon_index: field(56)? as i32,
        show_command: field(60)?,
        hotkey: u16_at(data, 64).ok_or_else(|| error(64, "header truncated"))?,
        target: Vec::new(),
        volume: None,
        local_path: String::new(),
        network_path: String::new(),
        network_device: String::new(),
        network_provider: None,
        common_path: String::new(),
        name: String::new(),
        relative_path: String::new(),
        working_dir: String::new(),
        arguments: String::new(),
        icon_location: String::new(),
        environment_target: String::new(),
        icon_environment_target: String::new(),
        darwin_id: String::new(),
        shim_layer: String::new(),
        known_folder: None,
        special_folder: None,
        console: None,
        console_code_page: None,
        properties: Vec::new(),
        vista_target: Vec::new(),
        tracker: None,
        blocks: Vec::new(),
        problems: Vec::new(),
    };
    if u32_at(data, 72).is_none() {
        return Err(error(72, "header truncated"));
    }
    let mut at = HEADER_SIZE as usize;
    if link.has(0) {
        let Some(size) = u16_at(data, at).map(usize::from) else {
            link.problems
                .push("the target ID list is cut off".to_owned());
            return Ok(link);
        };
        let Some(list) = data.get(at + 2..at + 2 + size) else {
            link.problems.push(format!(
                "the target ID list ({size} bytes at {at}) runs past the end"
            ));
            return Ok(link);
        };
        link.target = items(list, code_page);
        at += 2 + size;
    }
    if link.has(1) {
        let Some(size) = u32_at(data, at).map(|n| n as usize) else {
            link.problems.push("the link info is cut off".to_owned());
            return Ok(link);
        };
        match data.get(at..at + size) {
            Some(info) => link_info(info, &mut link, code_page),
            None => link.problems.push(format!(
                "the link info ({size} bytes at {at}) runs past the end"
            )),
        }
        at += size;
    }
    at = string_data(data, at, &mut link, code_page);
    link.length = extra_data(data, at, &mut link, code_page);
    Ok(link)
}

fn items(list: &[u8], code_page: u16) -> Vec<Item> {
    item::items(list)
        .into_iter()
        .map(|i| item::decode_with(i, code_page))
        .collect()
}

/// The string data (MS-SHLLINK 2.4); returns where it ends.
///
/// A count is the number of characters that follow. Windows reads at most
/// 260 of the name, relative path and working directory: a malicious link
/// can give one of them a larger count, so that what follows it (the
/// arguments) is read from inside it by Windows, but hidden from a reader
/// that trusts the count (LnkParse3's `padded_cli_arguments`). When the
/// counts run past the end of the file, and capping those three at 260
/// characters makes the strings fit, they're read capped, as Windows reads
/// them, and that's a problem.
fn string_data(data: &[u8], at: usize, link: &mut Link, code_page: u16) -> usize {
    let unicode = link.has(7);
    let present: Vec<u32> = (2..=6).filter(|&bit| link.has(bit)).collect();
    let read = |cap: bool| -> (Vec<(u32, String)>, usize, bool) {
        let mut out = Vec::new();
        let mut at = at;
        for &bit in &present {
            let Some(mut chars) = u16_at(data, at).map(usize::from) else {
                return (out, at, false);
            };
            if cap && bit <= 4 {
                chars = chars.min(MAX_PATH);
            }
            let len = if unicode { chars * 2 } else { chars };
            let Some(bytes) = data.get(at + 2..at + 2 + len) else {
                return (out, at, false);
            };
            let text = if unicode {
                utf16(bytes)
            } else {
                codepage::decode(bytes, code_page)
            };
            out.push((bit, text));
            at += 2 + len;
        }
        (out, at, true)
    };
    let (mut strings, mut end, fits) = read(false);
    if !fits {
        let (capped, capped_end, capped_fits) = read(true);
        if capped_fits {
            link.problems.push(
                "string data longer than 260 characters (the name, relative path or working \
                 directory): read as Windows reads it, 260 characters each"
                    .to_owned(),
            );
            strings = capped;
            end = capped_end;
        } else {
            link.problems
                .push(format!("the string data runs past the end (at {end})"));
        }
    }
    for (bit, text) in strings {
        match bit {
            2 => link.name = text,
            3 => link.relative_path = text,
            4 => link.working_dir = text,
            5 => link.arguments = text,
            _ => link.icon_location = text,
        }
    }
    end
}

/// LinkInfo (MS-SHLLINK 2.3): the volume and local path, or the network
/// share, with Unicode forms when the header is long enough. An offset
/// into the header itself, or past the structure, is taken as absent: a
/// suffix offset of 0 would otherwise read the size field as text.
fn link_info(info: &[u8], link: &mut Link, code_page: u16) {
    let header = u32_at(info, 4).unwrap_or(0) as usize;
    let flags = u32_at(info, 8).unwrap_or(0);
    let offset = |at| valid_offset(info, at, header.max(0x1c));
    let unicode = header >= 0x24;
    if flags & 1 != 0 {
        if let Some(v) = offset(12).and_then(|o| info.get(o..)) {
            let label = match valid_offset(v, 12, 0x10) {
                Some(0x14) => valid_offset(v, 16, 0x14).map(|o| string_at(v, o, true, code_page)),
                Some(at) => Some(string_at(v, at, false, code_page)),
                None => None,
            };
            link.volume = Some(Volume {
                drive_type: u32_at(v, 4).unwrap_or(0),
                serial: u32_at(v, 8).unwrap_or(0),
                label: label.unwrap_or_default(),
            });
        }
        link.local_path = match (unicode.then(|| offset(28)).flatten(), offset(16)) {
            (Some(at), _) => string_at(info, at, true, code_page),
            (None, Some(at)) => string_at(info, at, false, code_page),
            (None, None) => String::new(),
        };
    }
    if flags & 2 != 0
        && let Some(n) = offset(20).and_then(|o| info.get(o..))
    {
        network_link(n, link, code_page);
    }
    link.common_path = match (unicode.then(|| offset(32)).flatten(), offset(24)) {
        (Some(at), _) => string_at(info, at, true, code_page),
        (None, Some(at)) => string_at(info, at, false, code_page),
        (None, None) => String::new(),
    };
}

/// CommonNetworkRelativeLink (MS-SHLLINK 2.3.2): the share, and when its
/// flags say so the drive it was mapped to and the network provider.
fn network_link(n: &[u8], link: &mut Link, code_page: u16) {
    let flags = u32_at(n, 4).unwrap_or(0);
    let name_at = valid_offset(n, 8, 0x14);
    // Unicode offsets follow when the name's offset is past them.
    let unicode = name_at.is_some_and(|at| at > 0x14);
    let text = |ansi_at: usize, unicode_at: usize| -> String {
        if unicode {
            valid_offset(n, unicode_at, 0x1c)
                .map(|o| string_at(n, o, true, code_page))
                .unwrap_or_default()
        } else {
            valid_offset(n, ansi_at, 0x14)
                .map(|o| string_at(n, o, false, code_page))
                .unwrap_or_default()
        }
    };
    if name_at.is_some() {
        link.network_path = text(8, 20);
    }
    if flags & 1 != 0 {
        link.network_device = text(12, 24);
    }
    if flags & 2 != 0 {
        link.network_provider = u32_at(n, 16);
    }
}

/// The offset stored at `at` in `data`, when it points at or after
/// `min` (the end of the structure's header) and inside `data`.
fn valid_offset(data: &[u8], at: usize, min: usize) -> Option<usize> {
    u32_at(data, at)
        .map(|n| n as usize)
        .filter(|&o| o >= min && o < data.len())
}

/// Read the extra data blocks from `at`; returns where they end.
fn extra_data(data: &[u8], mut at: usize, link: &mut Link, code_page: u16) -> usize {
    while let Some(size) = u32_at(data, at).map(|n| n as usize) {
        if size < 4 {
            // The terminal block.
            return at + 4;
        }
        let Some(signature) = u32_at(data, at + 4) else {
            link.problems
                .push(format!("the extra data block at {at} is cut off"));
            return data.len();
        };
        if size < 8 || at + size > data.len() {
            link.problems.push(format!(
                "the extra data block at {at} ({}, {size} bytes) runs past the end",
                block_name(signature)
            ));
            return data.len();
        }
        let block = &data[at..at + size];
        link.blocks.push(signature);
        extra_block(signature, block, link, code_page);
        at += size;
    }
    link.problems
        .push("the extra data has no terminal block".to_owned());
    data.len()
}

/// Decode one extra data block (MS-SHLLINK 2.5).
fn extra_block(signature: u32, block: &[u8], link: &mut Link, code_page: u16) {
    // ANSI text at 8 (260 bytes), then Unicode at 268 (520 bytes): the
    // environment, icon environment and Darwin blocks.
    let ansi_and_unicode = |block: &[u8]| {
        let unicode = utf16(block.get(268..788).unwrap_or_default());
        if unicode.is_empty() {
            codepage::decode(block.get(8..268).unwrap_or_default(), code_page)
        } else {
            unicode
        }
    };
    match signature {
        0xa000_0001 => link.environment_target = ansi_and_unicode(block),
        0xa000_0002 => link.console = console(block),
        0xa000_0003 => link.tracker = tracker(block, code_page),
        0xa000_0004 => link.console_code_page = u32_at(block, 8),
        0xa000_0005 => {
            link.special_folder = u32_at(block, 8).zip(u32_at(block, 12));
        }
        0xa000_0006 => link.darwin_id = ansi_and_unicode(block),
        0xa000_0007 => link.icon_environment_target = ansi_and_unicode(block),
        0xa000_0008 => link.shim_layer = utf16(block.get(8..).unwrap_or_default()),
        0xa000_0009 => {
            link.properties = property::parse(block.get(8..).unwrap_or_default(), code_page);
        }
        0xa000_000b => {
            link.known_folder = block.get(8..24).and_then(item::guid).zip(u32_at(block, 24));
        }
        0xa000_000c => {
            link.vista_target = items(block.get(8..).unwrap_or_default(), code_page);
        }
        _ => {}
    }
}

/// The console data block's fields.
fn console(block: &[u8]) -> Option<Console> {
    let i16_at = |at| u16_at(block, at).map(|n| n as i16);
    let flag = |at| u32_at(block, at).map(|n| n != 0);
    let mut color_table = [0u32; 16];
    for (i, color) in color_table.iter_mut().enumerate() {
        *color = u32_at(block, 140 + 4 * i)?;
    }
    Some(Console {
        fill_attributes: u16_at(block, 8)?,
        popup_fill_attributes: u16_at(block, 10)?,
        screen_buffer_size: (i16_at(12)?, i16_at(14)?),
        window_size: (i16_at(16)?, i16_at(18)?),
        window_origin: (i16_at(20)?, i16_at(22)?),
        font_size: u32_at(block, 32)?,
        font_family: u32_at(block, 36)?,
        font_weight: u32_at(block, 40)?,
        face_name: utf16(block.get(44..108)?),
        cursor_size: u32_at(block, 108)?,
        full_screen: flag(112)?,
        quick_edit: flag(116)?,
        insert_mode: flag(120)?,
        auto_position: flag(124)?,
        history_buffer_size: u32_at(block, 128)?,
        history_buffers: u32_at(block, 132)?,
        history_no_dup: flag(136)?,
        color_table,
    })
}

/// The tracker block: machine name, then the droid (volume and object
/// identifiers) and birth droid.
fn tracker(block: &[u8], code_page: u16) -> Option<Tracker> {
    let machine_id = codepage::decode(block.get(16..32)?, code_page);
    let volume_id = item::guid(block.get(32..48)?)?;
    let object = block.get(48..64)?;
    let object_id = item::guid(object)?;
    let (created, mac) = item::guid_v1(object).unwrap_or_default();
    let birth_volume_id = item::guid(block.get(64..80)?)?;
    let birth_object = block.get(80..96)?;
    let birth_object_id = item::guid(birth_object)?;
    let (birth_created, birth_mac) = item::guid_v1(birth_object).unwrap_or_default();
    Some(Tracker {
        machine_id,
        volume_id,
        object_id,
        mac,
        created,
        birth_volume_id,
        birth_object_id,
        birth_mac,
        birth_created,
    })
}
