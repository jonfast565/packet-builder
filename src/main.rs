mod commands;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use packet_builder::ir::Module;
use packet_builder::{GenOptions, Language, compile_file, generate_module};

/// Generate binary packet parsers and serializers from packet descriptions.
#[derive(Parser)]
#[command(name = "packet_builder", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate code.
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
    /// Decode bytes with a packet description and print the fields.
    Decode(DecodeArgs),
    /// Generate a Wireshark Lua dissector from the file's `dissector`
    /// declarations (or from --packet and the other options).
    Dissector(DissectorArgs),
    /// Write a Markdown reference with bit diagrams.
    Doc(commands::DocArgs),
    /// Write fuzzing harnesses that round-trip every packet.
    Fuzz(commands::FuzzArgs),
    /// Report wire-incompatible changes between two versions of a description.
    Diff(commands::DiffArgs),
    /// List the supported target languages.
    Languages,
}

#[derive(Args)]
struct DecodeArgs {
    /// Packet description file.
    input: PathBuf,

    /// The packet to decode.
    #[arg(short = 'k', long = "packet")]
    packet: String,

    /// The bytes as hex (spaces and colons are ignored).
    #[arg(long, required_unless_present_any = ["file", "pcap"], conflicts_with_all = ["file", "pcap"])]
    hex: Option<String>,

    /// A file holding the raw bytes.
    #[arg(long, conflicts_with = "pcap")]
    file: Option<PathBuf>,

    /// A pcap or pcapng capture; every frame is decoded.
    #[arg(long)]
    pcap: Option<PathBuf>,

    /// Skip this many bytes at the start of each input (54 skips Ethernet,
    /// IPv4 and TCP headers without options).
    #[arg(long, default_value_t = 0)]
    offset: usize,

    /// Decode packets back to back until the input ends (a stream of frames).
    #[arg(long)]
    all: bool,

    /// Print JSON, one object per decoded packet, instead of a tree.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct DissectorArgs {
    /// Packet description file.
    input: PathBuf,

    /// Output directory (required unless --stdout); writes <package>.lua.
    #[arg(short, long, required_unless_present = "stdout", conflicts_with = "stdout")]
    out: Option<PathBuf>,

    /// Print the dissector to stdout.
    #[arg(long)]
    stdout: bool,

    /// Only this packet's dissector; declared on the command line if the
    /// file has none for it.
    #[arg(short = 'k', long = "packet")]
    packet: Option<String>,

    /// The protocol's name (with --packet).
    #[arg(long, requires = "packet")]
    name: Option<String>,

    /// The protocol's filter name and field prefix (with --packet).
    #[arg(long, requires = "packet")]
    abbrev: Option<String>,

    /// Register in a dissector table, e.g. --table tcp.port=5190 (with --packet; repeatable).
    #[arg(long = "table", requires = "packet")]
    tables: Vec<String>,

    /// Also try the dissector on any TCP/UDP payload (with --packet).
    #[arg(long, requires = "packet")]
    heuristic: bool,

    /// The global table the file exports (packet_builder_<package>); taken
    /// from the input file name when omitted.
    #[arg(short, long)]
    package: Option<String>,
}

#[derive(Args)]
struct GenerateArgs {
    /// Packet description file.
    input: PathBuf,

    /// Output directory (required unless --stdout).
    #[arg(short, long, required_unless_present = "stdout", conflicts_with = "stdout")]
    out: Option<PathBuf>,

    /// Target languages, comma separated (all when omitted). See `languages`.
    #[arg(short, long = "lang", value_delimiter = ',', value_parser = parse_language)]
    langs: Vec<Language>,

    /// Output file stem; also the Go package, C# namespace and C header guard.
    /// Taken from the input file name when omitted (`oscar.packet` → `oscar`).
    #[arg(short, long)]
    package: Option<String>,

    /// Print the generated code to stdout instead of writing files (one language only).
    #[arg(long)]
    stdout: bool,

    /// Decoded byte buffers (and strings, where the language allows) refer
    /// to the input instead of copying it.
    #[arg(long)]
    zero_copy: bool,
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
        Command::Generate(args) => generate(args),
        Command::Check { inputs } => check(&inputs),
        Command::Layout { input, packets } => layout(&input, &packets),
        Command::Decode(args) => decode(args),
        Command::Dissector(args) => dissector(args),
        Command::Doc(args) => commands::doc(args),
        Command::Fuzz(args) => commands::fuzz(args),
        Command::Diff(args) => commands::diff(args),
        Command::Languages => {
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

/// A package name from the input file stem: characters that are not valid
/// in identifiers become `_` (`my-proto.packet` → `my_proto`).
fn package_from(input: &Path) -> String {
    let stem = input.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let mut name: String = stem.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
        name.insert(0, 'p');
    }
    name
}

/// Read and compile a file; errors are rendered with source snippets.
fn load(input: &Path) -> Result<Module, String> {
    compile_file(input).map_err(|e| e.render())
}

fn dissector(args: DissectorArgs) -> Result<(), String> {
    use packet_builder::ir::Dissector;
    let module = load(&args.input)?;
    let mut list = module.dissectors.clone();
    if let Some(packet) = &args.packet {
        let p = module
            .packets
            .iter()
            .find(|p| &p.name == packet)
            .ok_or_else(|| format!("no packet named `{}` in {}", packet, args.input.display()))?;
        if !p.params.is_empty() {
            return Err(format!("packet `{}` takes parameters, so it cannot have a dissector of its own", packet));
        }
        let mut d = list.iter().find(|d| &d.packet == packet).cloned().unwrap_or_else(|| Dissector::new(packet));
        if let Some(name) = args.name {
            d.name = name;
        }
        if let Some(abbrev) = args.abbrev {
            Dissector::check_abbrev(&abbrev)?;
            d.abbrev = abbrev;
        }
        for t in &args.tables {
            let (table, value) = t.split_once('=').ok_or_else(|| format!("--table {}: expected TABLE=VALUE", t))?;
            let value = parse_number(value).ok_or_else(|| format!("--table {}: bad value", t))?;
            d.tables.push((table.to_string(), value));
        }
        d.heuristic |= args.heuristic;
        list = vec![d];
    }
    if list.is_empty() {
        return Err(format!(
            "{} declares no dissector; add one (dissector Packet {{ abbrev \"proto\" }}) or pass --packet",
            args.input.display()
        ));
    }
    let package = args.package.unwrap_or_else(|| package_from(&args.input));
    let lua = packet_builder::generate_dissector(&module, &list, &package);
    if args.stdout {
        print!("{}", lua);
        return Ok(());
    }
    let out = args.out.expect("clap requires --out unless --stdout");
    fs::create_dir_all(&out).map_err(|e| format!("cannot create {}: {}", out.display(), e))?;
    let path = out.join(format!("{}.lua", package));
    fs::write(&path, lua).map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
    println!("wrote {}", path.display());
    Ok(())
}

/// A decimal or 0x-prefixed hex number.
fn parse_number(s: &str) -> Option<u64> {
    match s.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

fn generate(args: GenerateArgs) -> Result<(), String> {
    let module = load(&args.input)?;
    let langs = if args.langs.is_empty() { Language::ALL.to_vec() } else { args.langs };
    let opts =
        GenOptions { package: args.package.unwrap_or_else(|| package_from(&args.input)), zero_copy: args.zero_copy };

    if args.stdout {
        if langs.len() != 1 {
            return Err("--stdout needs exactly one --lang".into());
        }
        print!("{}", generate_module(&module, langs[0], &opts));
        return Ok(());
    }

    let out = args.out.expect("clap requires --out unless --stdout");
    fs::create_dir_all(&out).map_err(|e| format!("cannot create {}: {}", out.display(), e))?;
    for lang in langs {
        let path = out.join(format!("{}.{}", opts.package, lang.extension()));
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
            let note = if m.is_decode_only() { " (from `remaining`, decode only)" } else { "" };
            println!("  {:>8}  {:>6}  {:<24} calculated{}", "-", "-", m.name, note);
        }
        println!();
    }
    if only.is_empty() {
        print_constants(&module);
    }
    Ok(())
}

/// The file's named constants, after the packets.
fn print_constants(module: &packet_builder::ir::Module) {
    use packet_builder::ir::{Constant, ValueType};
    if module.constants.is_empty() && module.categories.is_empty() {
        return;
    }
    let ty = |t: &ValueType| match t {
        ValueType::Int { width, signed } => format!("{}{}", if *signed { "i" } else { "u" }, width),
        _ => String::new(),
    };
    let row = |name: &str, c: &Constant| {
        let note = c.note.as_ref().map(|n| format!("  {}", n)).unwrap_or_default();
        println!("  {:<24} {:>6}  {:>20}{}", name, ty(&c.ty), c.literal(), note);
    };
    if !module.constants.is_empty() {
        println!("constants:");
    }
    for c in &module.constants {
        row(&c.name, c);
    }
    for cat in &module.categories {
        println!("category {} ({}):", cat.name, ty(&cat.ty));
        for c in &cat.members {
            row(&format!("{}.{}", cat.name, c.name), c);
        }
    }
    println!();
}

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    let digits = digits.strip_prefix("0x").unwrap_or(&digits);
    if !digits.len().is_multiple_of(2) {
        return Err("hex input has an odd number of digits".into());
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|_| format!("invalid hex `{}`", &digits[i..i + 2])))
        .collect()
}

fn decode(args: DecodeArgs) -> Result<(), String> {
    use packet_builder::ir::interp;

    let module = load(&args.input)?;
    if !module.packets.iter().any(|p| p.name == args.packet) {
        return Err(format!("no packet named `{}` in {}", args.packet, args.input.display()));
    }
    let read = |path: &Path| fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e));
    let inputs: Vec<(String, Vec<u8>)> = if let Some(hex) = &args.hex {
        vec![(String::new(), parse_hex(hex)?)]
    } else if let Some(path) = &args.file {
        vec![(String::new(), read(path)?)]
    } else {
        let path = args.pcap.as_ref().expect("clap requires an input");
        let frames = packet_builder::pcap::read(&read(path)?).map_err(|e| format!("{}: {}", path.display(), e))?;
        frames.into_iter().enumerate().map(|(i, f)| (format!("frame {}", i + 1), f.data)).collect()
    };

    let mut failed = false;
    for (label, data) in inputs {
        let data = data.get(args.offset..).unwrap_or(&[]);
        let mut r = interp::Reader::new(data);
        let mut n = 0;
        let mut ok = true;
        loop {
            let at = r.position_bits() / 8;
            let heading = match (label.is_empty(), args.all) {
                (true, false) => String::new(),
                (true, true) => format!("packet {} at byte {}", n + 1, at),
                (false, false) => label.clone(),
                (false, true) => format!("{}, packet {} at byte {}", label, n + 1, at),
            };
            match interp::decode_from(&module, &args.packet, &mut r) {
                Ok(v) if args.json => println!("{}", v.to_json()),
                Ok(v) => {
                    if !heading.is_empty() {
                        println!("{}:", heading);
                    }
                    print!("{}", interp::render(&module, &v));
                }
                Err(e) => {
                    let prefix = if heading.is_empty() { String::new() } else { format!("{}: ", heading) };
                    eprintln!("{}error: {}", prefix, e);
                    ok = false;
                    break;
                }
            }
            n += 1;
            if !args.all || r.remaining_bits() == 0 {
                break;
            }
        }
        failed |= !ok;
        let left = r.remaining_bits() / 8;
        if ok && !args.all && left > 0 && !args.json {
            println!("({} trailing byte(s) not decoded)", left);
        }
        if !args.json {
            println!();
        }
    }
    if failed { Err(String::new()) } else { Ok(()) }
}
