use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use packet_builder::ir::Module;
use packet_builder::{GenOptions, Language, compile, generate_module};

/// Generate binary packet parsers and serializers from packet descriptions.
#[derive(Parser)]
#[command(name = "packet_builder", version, about, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Without a subcommand, `generate` runs with these arguments.
    #[command(flatten)]
    generate: GenerateArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Generate code (the default command).
    #[command(visible_alias = "gen")]
    Generate(GenerateArgs),
    /// Validate packet descriptions without writing anything.
    Check {
        /// Packet description files.
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
    },
    /// Show the byte/bit offset and size of every field, including padding.
    Layout {
        /// Packet description file.
        input: PathBuf,
        /// Only show these packets.
        #[arg(short = 'k', long = "packet")]
        packets: Vec<String>,
    },
    /// List the supported target languages.
    Languages,
}

#[derive(Args)]
struct GenerateArgs {
    /// Packet description file.
    #[arg(default_value = "examples/oscar.packet")]
    input: PathBuf,

    /// Output directory.
    #[arg(short, long, default_value = "results")]
    out: PathBuf,

    /// Target languages, comma separated (default: all). See `languages`.
    #[arg(short, long = "lang", value_delimiter = ',', value_parser = parse_language)]
    langs: Vec<Language>,

    /// Output file stem; also the Go package, C# namespace and C header guard.
    #[arg(short, long, default_value = "packets")]
    package: String,

    /// Print the generated code to stdout instead of writing files (one language only).
    #[arg(long)]
    stdout: bool,
}

fn parse_language(s: &str) -> Result<Language, String> {
    Language::from_name(s.trim()).ok_or_else(|| {
        let names: Vec<&str> = Language::ALL.iter().map(|l| l.name()).collect();
        format!("unknown language `{}` (expected one of: {})", s, names.join(", "))
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Generate(args)) => generate(args),
        None => generate(cli.generate),
        Some(Command::Check { inputs }) => check(&inputs),
        Some(Command::Layout { input, packets }) => layout(&input, &packets),
        Some(Command::Languages) => {
            for l in Language::ALL {
                println!("{:<8} .{}", l.name(), l.extension());
            }
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("{}", message.trim_end());
            }
            ExitCode::FAILURE
        }
    }
}

/// Read and compile a file; errors are rendered with source snippets.
fn load(input: &Path) -> Result<Module, String> {
    let source = fs::read_to_string(input).map_err(|e| format!("cannot read {}: {}", input.display(), e))?;
    compile(&source).map_err(|e| e.render(&input.display().to_string(), &source))
}

fn generate(args: GenerateArgs) -> Result<(), String> {
    let module = load(&args.input)?;
    let langs = if args.langs.is_empty() { Language::ALL.to_vec() } else { args.langs };
    let opts = GenOptions { package: args.package };

    if args.stdout {
        if langs.len() != 1 {
            return Err("--stdout needs exactly one --lang".into());
        }
        print!("{}", generate_module(&module, langs[0], &opts));
        return Ok(());
    }

    fs::create_dir_all(&args.out).map_err(|e| format!("cannot create {}: {}", args.out.display(), e))?;
    for lang in langs {
        let path = args.out.join(format!("{}.{}", opts.package, lang.extension()));
        fs::write(&path, generate_module(&module, lang, &opts))
            .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

fn check(inputs: &[PathBuf]) -> Result<(), String> {
    let mut failed = false;
    for input in inputs {
        match load(input) {
            Ok(m) => println!("{}: ok ({} packet(s))", input.display(), m.packets.len()),
            Err(e) => {
                eprint!("{}", e);
                failed = true;
            }
        }
    }
    if failed { Err(String::new()) } else { Ok(()) }
}

fn layout(input: &Path, only: &[String]) -> Result<(), String> {
    let module = load(input)?;
    for name in only {
        if !module.packets.iter().any(|p| &p.name == name) {
            return Err(format!("no packet named `{}` in {}", name, input.display()));
        }
    }
    let fmt_bits = |bits: Option<u64>| match bits {
        None => "?".to_string(),
        Some(b) if b % 8 == 0 => format!("{}", b / 8),
        Some(b) => format!("{}.{}", b / 8, b % 8),
    };
    println!("Offsets and sizes are in bytes; 12.4 means byte 12 plus 4 bits. ? depends on the data.\n");
    for p in module.packets.iter().filter(|p| only.is_empty() || only.contains(&p.name)) {
        let size = match p.fixed_bits {
            Some(b) => format!("{} byte(s)", fmt_bits(Some(b))),
            None => format!("variable, at least {} byte(s)", fmt_bits(Some(p.min_bits))),
        };
        println!("packet {}: {}, alignment {}", p.name, size, p.alignment);
        println!("  {:>8}  {:>6}  {:<24} type", "offset", "size", "field");
        for row in module.layout(p) {
            let name = if row.nested { format!("  {}", row.name) } else { row.name.clone() };
            println!("  {:>8}  {:>6}  {:<24} {}", fmt_bits(row.offset_bits), fmt_bits(row.size_bits), name, row.kind);
        }
        for m in p.members.iter().filter(|m| matches!(m.kind, packet_builder::ir::MemberKind::Calculated(_))) {
            println!("  {:>8}  {:>6}  {:<24} calculated", "-", "-", m.name);
        }
        println!();
    }
    Ok(())
}
