//! LnkParse3's test links (MIT, Matúš Jasnický; `tests/fixtures/lnkparse3/`,
//! with LnkParse3's output for each): the extra data blocks the Eric
//! Zimmerman set holds few of (console, Darwin, icon environment, known and
//! special folders, data after the terminal block, an unknown block), a
//! command line hidden behind padding, network shares, and damaged links.
//! Every field both parsers read is compared.

// One comparison per field, LnkParse3's JSON sections in short names.
#![allow(clippy::many_single_char_names, clippy::too_many_lines)]

use std::fs;
use std::path::Path;

use serde_json::Value;
use shell::lnk::{self, Link};

fn dir() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/lnkparse3"
    ))
}

/// A JSON string, or "" for null or missing.
fn text(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_owned()
}

fn guid(v: &Value) -> String {
    let g = text(v);
    if g.is_empty() {
        g
    } else {
        format!("{{{}}}", g.trim_matches(['{', '}']).to_uppercase())
    }
}

/// The differences between our reading and LnkParse3's, as
/// `field: ours | theirs`.
fn differences(link: &Link, expected: &Value) -> Vec<String> {
    let mut diffs = Vec::new();
    let mut check = |field: &str, ours: String, theirs: String| {
        if ours != theirs {
            diffs.push(format!("{field}: {ours:?} | {theirs:?}"));
        }
    };
    let h = &expected["header"];
    check(
        "flags",
        link.flags.to_string(),
        h["r_link_flags"].to_string(),
    );
    check(
        "attributes",
        link.attributes.to_string(),
        h["r_file_flags"].to_string(),
    );
    check("size", link.size.to_string(), h["file_size"].to_string());
    check(
        "icon_index",
        link.icon_index.to_string(),
        h["icon_index"].to_string(),
    );
    check("hotkey", link.hotkey.to_string(), h["r_hotkey"].to_string());
    let show = match h["windowstyle"].as_str() {
        Some("SW_SHOWMAXIMIZED") => "SW_SHOWMAXIMIZED",
        Some("SW_SHOWMINNOACTIVE") => "SW_SHOWMINNOACTIVE",
        _ => "SW_SHOWNORMAL",
    };
    check(
        "show",
        link.show_command_name()
            .unwrap_or("SW_SHOWNORMAL")
            .to_owned(),
        show.to_owned(),
    );
    let d = &expected["data"];
    check("name", link.name.clone(), text(&d["description"]));
    check(
        "relative_path",
        link.relative_path.clone(),
        text(&d["relative_path"]),
    );
    check(
        "working_dir",
        link.working_dir.clone(),
        text(&d["working_directory"]),
    );
    check(
        "arguments",
        link.arguments.clone(),
        text(&d["command_line_arguments"]),
    );
    check(
        "icon_location",
        link.icon_location.clone(),
        text(&d["icon_location"]),
    );
    let li = &expected["link_info"];
    if li.is_object() {
        let local = [&li["local_base_path_unicode"], &li["local_base_path"]]
            .into_iter()
            .map(text)
            .find(|s| !s.is_empty())
            .unwrap_or_default();
        check("local_path", link.local_path.clone(), local);
        let loc = &li["location_info"];
        if loc.is_object() {
            let v = link.volume.as_ref();
            let drive = loc["r_drive_type"]
                .as_u64()
                .map_or(String::new(), |n| n.to_string());
            check(
                "drive_type",
                v.map_or(String::new(), |v| v.drive_type.to_string()),
                drive,
            );
            let serial = text(&loc["drive_serial_number"]);
            let serial = u32::from_str_radix(serial.trim_start_matches("0x"), 16)
                .map_or(String::new(), |n| n.to_string());
            check(
                "serial",
                v.map_or(String::new(), |v| v.serial.to_string()),
                serial,
            );
            let label = [&loc["volume_label_unicode"], &loc["volume_label"]]
                .into_iter()
                .map(text)
                .find(|s| !s.is_empty())
                .unwrap_or_default();
            check("label", v.map_or(String::new(), |v| v.label.clone()), label);
        }
        let net = &li["location_info"];
        if text(&li["location"]) == "Network" {
            check(
                "network_path",
                link.network_path.clone(),
                text(&net["net_name"]),
            );
            check(
                "network_device",
                link.network_device.clone(),
                text(&net["device_name"]),
            );
        }
    }
    let x = &expected["extra"];
    let block = |name: &str, field: &str| text(&x[name][field]);
    let either = |name: &str| {
        let u = block(name, "target_unicode");
        if u.is_empty() {
            block(name, "target_ansi")
        } else {
            u
        }
    };
    check(
        "environment_target",
        link.environment_target.clone(),
        either("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK"),
    );
    check(
        "icon_environment_target",
        link.icon_environment_target.clone(),
        either("ICON_LOCATION_BLOCK"),
    );
    let darwin = block("DARWIN_BLOCK", "darwin_data_unicode");
    let darwin = if darwin.is_empty() {
        block("DARWIN_BLOCK", "darwin_data_ansi")
    } else {
        darwin
    };
    check("darwin_id", link.darwin_id.clone(), darwin);
    let kf = &x["KNOWN_FOLDER_LOCATION_BLOCK"];
    check(
        "known_folder",
        link.known_folder
            .as_ref()
            .map_or(String::new(), |(g, o)| format!("{g} {o}")),
        if kf.is_object() {
            format!("{} {}", guid(&kf["known_folder_id"]), kf["offset"])
        } else {
            String::new()
        },
    );
    let sf = &x["SPECIAL_FOLDER_LOCATION_BLOCK"];
    check(
        "special_folder",
        link.special_folder
            .map_or(String::new(), |(id, o)| format!("{id} {o}")),
        if sf.is_object() {
            format!("{} {}", sf["special_folder_id"], sf["offset"])
        } else {
            String::new()
        },
    );
    let tr = &x["DISTRIBUTED_LINK_TRACKER_BLOCK"];
    if tr.is_object() {
        let t = link.tracker.as_ref().expect("tracker");
        check(
            "machine_id",
            t.machine_id.clone(),
            text(&tr["machine_identifier"]),
        );
        check(
            "volume_id",
            t.volume_id.clone(),
            guid(&tr["droid_volume_identifier"]),
        );
        check(
            "object_id",
            t.object_id.clone(),
            guid(&tr["droid_file_identifier"]),
        );
        check(
            "birth_volume_id",
            t.birth_volume_id.clone(),
            guid(&tr["birth_droid_volume_identifier"]),
        );
        check(
            "birth_object_id",
            t.birth_object_id.clone(),
            guid(&tr["birth_droid_file_identifier"]),
        );
    }
    let c = &x["CONSOLE_PROPERTIES_BLOCK"];
    if c.is_object() {
        let ours = link.console.as_ref().expect("console");
        let n = |k: &str| c[k].as_i64().unwrap_or(-1);
        check(
            "console",
            format!(
                "{} {} {:?} {:?} {:?} {} {} {} {} {} {}",
                ours.fill_attributes,
                ours.popup_fill_attributes,
                ours.screen_buffer_size,
                ours.window_size,
                ours.window_origin,
                ours.font_size,
                ours.font_weight,
                ours.face_name,
                ours.cursor_size,
                ours.history_buffer_size,
                ours.history_buffers,
            ),
            format!(
                "{} {} ({}, {}) ({}, {}) ({}, {}) {} {} {} {} {} {}",
                n("fill_attributes"),
                n("popup_fill_attributes"),
                n("screen_buffer_size_x"),
                n("screen_buffer_size_y"),
                n("window_size_x"),
                n("window_size_y"),
                n("window_origin_x"),
                n("window_origin_y"),
                n("font_size"),
                n("font_weight"),
                text(&c["face_name"]),
                n("cursor_size"),
                n("history_buffer_size"),
                n("number_of_history_buffers"),
            ),
        );
    }
    diffs
}

#[test]
fn every_field_both_read_agrees() {
    let mut compared = 0;
    let mut all = Vec::new();
    let mut names: Vec<String> = fs::read_dir(dir())
        .unwrap()
        .filter_map(|e| {
            let n = e.unwrap().file_name().into_string().unwrap();
            n.strip_suffix(".lnk").map(str::to_owned)
        })
        .collect();
    names.sort();
    for name in names {
        let data = fs::read(dir().join(format!("{name}.lnk"))).unwrap();
        let expected: Value =
            serde_json::from_slice(&fs::read(dir().join(format!("{name}.json"))).unwrap()).unwrap();
        match lnk::parse(&data) {
            Ok(link) => {
                compared += 1;
                for d in differences(&link, &expected) {
                    all.push(format!("{name}: {d}"));
                }
            }
            Err(e) => all.push(format!("{name}: not parsed: {e}")),
        }
    }
    assert!(compared > 30);
    assert!(all.is_empty(), "{}", all.join("\n"));
}

#[test]
fn the_console_color_table() {
    // LnkParse3 doesn't decode the table (it reads 0): this one is a
    // PowerShell console's, Windows' defaults but for its blue (0x562401)
    // and off-white (0xF0EDEE).
    let data = fs::read(dir().join("console_properties_block.lnk")).unwrap();
    let console = lnk::parse(&data).unwrap().console.unwrap();
    assert_eq!(
        console.color_table,
        [
            0x00_0000, 0x80_0000, 0x00_8000, 0x80_8000, 0x00_0080, 0x56_2401, 0xf0_edee, 0xc0_c0c0,
            0x80_8080, 0xff_0000, 0x00_ff00, 0xff_ff00, 0x00_00ff, 0xff_00ff, 0x00_ffff, 0xff_ffff,
        ]
    );
    assert_eq!(console.face_name, "Lucida Console");
    assert!(console.quick_edit && console.insert_mode);
}

#[test]
fn the_command_line_hidden_behind_padding() {
    // The working directory claims 1,693 characters; Windows reads 260, so
    // the 1,431-character arguments start inside them.
    let data = fs::read(dir().join("padded_cli_arguments.lnk")).unwrap();
    let link = lnk::parse(&data).unwrap();
    assert_eq!(link.working_dir.trim_end(), r"C:\Windows\System32");
    assert_eq!(link.arguments.chars().count(), 1431);
    assert!(link.arguments.starts_with("/c \"set PATH="));
    assert!(link.problems[0].starts_with("string data longer than 260 characters"));
}

#[test]
fn data_after_the_terminal_block() {
    // Exactly the links LnkParse3 finds appended data in (unknown_target:
    // 67 KB after the terminal block) end before the file does.
    let mut appended = Vec::new();
    for e in fs::read_dir(dir()).unwrap() {
        let name = e.unwrap().file_name().into_string().unwrap();
        let Some(stem) = name.strip_suffix(".lnk") else {
            continue;
        };
        let data = fs::read(dir().join(&name)).unwrap();
        let expected: Value =
            serde_json::from_slice(&fs::read(dir().join(format!("{stem}.json"))).unwrap()).unwrap();
        let theirs = expected["extra"]["TERMINAL_BLOCK"]["appended_data_sha256"].is_string();
        if let Ok(link) = lnk::parse(&data) {
            assert_eq!(link.length < data.len(), theirs, "{stem}");
            if theirs {
                appended.push(stem.to_owned());
            }
        }
    }
    assert_eq!(appended, ["unknown_target"]);
}
