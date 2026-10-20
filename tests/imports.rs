//! `import "file.packet"`: loading, cycles and errors in imported files.

use std::fs;
use std::path::{Path, PathBuf};

use packet_builder::{compile, compile_file};

/// A fresh directory holding `files` (name, contents).
fn tree(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("imports").join(name);
    let _ = fs::remove_dir_all(&dir);
    for (file, text) in files {
        let path = dir.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    dir
}

#[test]
fn imported_packets_and_constants_are_available() {
    let dir = tree(
        "basic",
        &[
            ("common/header.packet", "const MAGIC uint8 = 0x2a\npacket Header be { magic uint8 == MAGIC, len uint8 }"),
            (
                "main.packet",
                "import \"common/header.packet\"\npacket Frame be { h Header, data bytes[h_len], calc h_len uint8 = 1 }",
            ),
        ],
    );
    let m = compile_file(&dir.join("main.packet")).unwrap_or_else(|e| panic!("{}", e.render()));
    let names: Vec<&str> = m.packets.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["Header", "Frame"]);
    assert_eq!(m.constants[0].name, "MAGIC");
}

#[test]
fn a_file_imported_twice_is_loaded_once() {
    let dir = tree(
        "diamond",
        &[
            ("base.packet", "packet Base { a uint8 }"),
            ("left.packet", "import \"base.packet\"\npacket Left { b Base }"),
            ("right.packet", "import \"base.packet\"\npacket Right { b Base }"),
            ("main.packet", "import \"left.packet\"\nimport \"right.packet\"\npacket Main { l Left, r Right }"),
        ],
    );
    let m = compile_file(&dir.join("main.packet")).unwrap_or_else(|e| panic!("{}", e.render()));
    assert_eq!(m.packets.len(), 4);
}

#[test]
fn import_cycles_are_errors() {
    let dir = tree(
        "cycle",
        &[
            ("a.packet", "import \"b.packet\"\npacket A { x uint8 }"),
            ("b.packet", "import \"a.packet\"\npacket B { y uint8 }"),
        ],
    );
    let e = compile_file(&dir.join("a.packet")).unwrap_err();
    let text = e.render();
    assert!(text.contains("import cycle: a.packet -> b.packet -> a.packet"), "{}", text);
    assert!(text.contains("b.packet"), "{}", text);
}

#[test]
fn errors_name_the_file_they_are_in() {
    let dir = tree(
        "located",
        &[
            ("lib.packet", "packet Lib {\n  a uint8,\n  b bytes[nope]\n}"),
            ("main.packet", "import \"lib.packet\"\npacket Main { l Lib }"),
        ],
    );
    let text = compile_file(&dir.join("main.packet")).unwrap_err().render();
    assert!(text.contains("lib.packet:3"), "{}", text);
    assert!(text.contains("unknown field `nope`"), "{}", text);

    let dir = tree("syntax", &[("lib.packet", "packet Lib { a uint8 ]"), ("main.packet", "import \"lib.packet\"")]);
    let text = compile_file(&dir.join("main.packet")).unwrap_err().render();
    assert!(text.contains("lib.packet:1"), "{}", text);
}

#[test]
fn names_clash_across_files() {
    let dir = tree(
        "clash",
        &[("lib.packet", "packet Same { a uint8 }"), ("main.packet", "import \"lib.packet\"\npacket Same { b uint8 }")],
    );
    let text = compile_file(&dir.join("main.packet")).unwrap_err().render();
    assert!(text.contains("packet `Same` is declared more than once"), "{}", text);
    assert!(text.contains("main.packet"), "{}", text);
}

#[test]
fn missing_files() {
    let dir = tree("missing", &[("main.packet", "import \"gone.packet\"\npacket A { x uint8 }")]);
    let text = compile_file(&dir.join("main.packet")).unwrap_err().render();
    assert!(text.contains("cannot read") && text.contains("gone.packet"), "{}", text);
    let text = compile_file(&dir.join("absent.packet")).unwrap_err().render();
    assert!(text.contains("cannot read"), "{}", text);
}

#[test]
fn compile_without_a_file_rejects_imports() {
    let e = compile("import \"x.packet\"\npacket A { x uint8 }").unwrap_err();
    assert!(e.to_string().contains("compile_file"), "{}", e);
}
