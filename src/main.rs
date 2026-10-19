use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use packet_builder::{GenOptions, Language, compile, generate_module};

const USAGE: &str = "\
usage: packet_builder [INPUT.packet] [-o OUT_DIR] [-l LANG[,LANG...]] [-p PACKAGE]

  INPUT     packet description (default: examples/oscar.packet)
  -o DIR    output directory (default: ./results)
  -l LANGS  comma separated list of c, rust, zig, csharp, python, go (default: all)
  -p NAME   output file stem / Go package / C# namespace (default: packets)
";

fn main() -> ExitCode {
    let mut input = PathBuf::from("examples/oscar.packet");
    let mut out_dir = PathBuf::from("./results");
    let mut langs: Vec<Language> = Language::ALL.to_vec();
    let mut opts = GenOptions::default();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| {
            args.next().unwrap_or_else(|| {
                eprintln!("missing value for {}\n\n{}", flag, USAGE);
                std::process::exit(2);
            })
        };
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{}", USAGE);
                return ExitCode::SUCCESS;
            }
            "-o" | "--out" => out_dir = PathBuf::from(value("-o")),
            "-p" | "--package" => opts.package = value("-p"),
            "-l" | "--lang" => {
                let mut parsed = Vec::new();
                for name in value("-l").split(',') {
                    match Language::from_name(name.trim()) {
                        Some(l) => parsed.push(l),
                        None => {
                            eprintln!("unknown language `{}`\n\n{}", name, USAGE);
                            return ExitCode::from(2);
                        }
                    }
                }
                langs = parsed;
            }
            other if other.starts_with('-') => {
                eprintln!("unknown option `{}`\n\n{}", other, USAGE);
                return ExitCode::from(2);
            }
            other => input = PathBuf::from(other),
        }
    }

    let source = match fs::read_to_string(&input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {}: {}", input.display(), e);
            return ExitCode::FAILURE;
        }
    };
    let module = match compile(&source) {
        Ok(m) => m,
        Err(e) => {
            eprint!("{}", e.render(&input.display().to_string(), &source));
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("cannot create {}: {}", out_dir.display(), e);
        return ExitCode::FAILURE;
    }
    for lang in langs {
        let code = generate_module(&module, lang, &opts);
        let path = out_dir.join(format!("{}.{}", opts.package, lang.extension()));
        if let Err(e) = fs::write(&path, code) {
            eprintln!("cannot write {}: {}", path.display(), e);
            return ExitCode::FAILURE;
        }
        println!("wrote {}", path.display());
    }
    ExitCode::SUCCESS
}
