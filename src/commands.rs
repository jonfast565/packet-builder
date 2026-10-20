//! The `doc`, `fuzz` and `diff` commands.

use std::fs;
use std::path::{Path, PathBuf};

use clap::Args;
use packet_builder::tools;

use crate::{load, package_from};

#[derive(Args)]
pub struct DocArgs {
    /// Packet description file.
    input: PathBuf,
    /// Output file (stdout when omitted).
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Document title (the file name when omitted).
    #[arg(long)]
    title: Option<String>,
}

pub fn doc(args: DocArgs) -> Result<(), String> {
    let module = load(&args.input)?;
    let title = args
        .title
        .unwrap_or_else(|| args.input.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    let text = tools::doc::document(&module, &title);
    match args.out {
        None => print!("{}", text),
        Some(path) => {
            fs::write(&path, text).map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
            println!("wrote {}", path.display());
        }
    }
    Ok(())
}

#[derive(Args)]
pub struct FuzzArgs {
    /// Packet description file.
    input: PathBuf,
    /// `rust` (a cargo-fuzz project) or `c` (libFuzzer harnesses).
    #[arg(short, long = "lang", default_value = "rust")]
    lang: String,
    /// Output directory.
    #[arg(short, long)]
    out: PathBuf,
    /// Package / file stem (the input file name when omitted).
    #[arg(short, long)]
    package: Option<String>,
}

pub fn fuzz(args: FuzzArgs) -> Result<(), String> {
    let module = load(&args.input)?;
    let package = args.package.unwrap_or_else(|| package_from(&args.input));
    let files = match args.lang.as_str() {
        "rust" => tools::fuzz::rust_project(&module, &package),
        "c" => tools::fuzz::c_harnesses(&module, &package),
        other => return Err(format!("fuzzing harnesses exist for rust and c, not `{}`", other)),
    };
    write_files(&args.out, &files)
}

fn write_files(dir: &Path, files: &[(String, String)]) -> Result<(), String> {
    for (name, text) in files {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
        }
        fs::write(&path, text).map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

#[derive(Args)]
pub struct DiffArgs {
    /// The old description.
    old: PathBuf,
    /// The new description.
    new: PathBuf,
}

/// Fails (exit status 1) when a change is wire-incompatible.
pub fn diff(args: DiffArgs) -> Result<(), String> {
    let (old, new) = (load(&args.old)?, load(&args.new)?);
    let changes = tools::diff::diff(&old, &new);
    if changes.is_empty() {
        println!("no wire changes");
        return Ok(());
    }
    for c in &changes {
        println!("{}: {}", if c.compatible { "compatible" } else { "incompatible" }, c.message);
    }
    if changes.iter().any(|c| !c.compatible) {
        return Err(String::new());
    }
    Ok(())
}
