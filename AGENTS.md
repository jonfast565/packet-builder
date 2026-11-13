# Notes for coding agents

packet-builder compiles `.packet` descriptions into decoders/encoders for C,
Rust, Go, Python, C#, Zig, Object Pascal, TypeScript, Lua, Java, Swift, Fortran, Ada and COBOL. See `README.md` for the language itself.

## Pipeline and layout

```
source ──parser──▶ PacketExprList ──ir::analyze──▶ ir::Module ──Backend──▶ code
```

| path | role |
|------|------|
| `src/parser/` | pest grammar (`grammar.pest`) → parse tree. `literals` validates numbers first; `items` (`TreeBuilder`) builds packets; `consts` builds `const` declarations; `expr` parses expressions; `types` maps type names. |
| `src/ast.rs` | parse-tree types (`TypeNode`, `ExprNode`, `PacketExpr`, ...). |
| `src/ir/model.rs` | the validated model every backend consumes: `Packet`, `Member`, `ValueType`, `Param`, `PacketRef`, unions and constants. |
| `src/ir/wire.rs` | how fields travel on the wire: `Codec`, `Count`, `StrMode`, `Step` (re-exported from `model`). |
| `src/ir/expr.rs` | type-checked expressions (`TExpr`). |
| `src/ir/analysis/` | builds the model. `packet.rs` is a `PacketBuilder` that runs the passes in order (declare → counts → calcs → derived → lay out → finish); `consts.rs` folds named constants into a `ConstTable` (run before packets) and checks `: Category` tags; `checks.rs` turns `==`/`in`/`strict` into checks; `versions.rs` runs first (`version N`, `@range`): it resolves ranges and merges re-declarations into one derivation/check per field, so later passes only see gated items, which lay out between `Step::OpenGate`/`CloseGate`; `bitfield.rs` lays out bitfield containers; `derive.rs` orders derived fields and their marks; `union.rs` lays out `switch` fields and `size n` windows; `repeat.rs` resolves `until`, `term` and text encodings; `params.rs` holds packet signatures (parameters, member types known before analysis), arguments, `at` fields and the analysis order, which lets packets contain themselves through arrays and `at`; `cursor.rs` tracks the bit offset; `typecheck.rs`, `codec.rs`, `context.rs`, `types.rs` hold the rest. |
| `src/ir/layout.rs` | the `layout` command's report. |
| `src/ir/interp/` | the reference interpreter: decodes/encodes a `Module` directly, using `runtime/rust.rs` (included as `interp::rt`). `show.rs` renders decoded values for the `decode` command. |
| `src/pcap.rs` | pcap/pcapng reading and pcap writing (no dependencies). |
| `src/generators/common/` | code shared by every backend (see below). |
| `src/generators/<lang>/` | one backend per language, always split the same way: `mod.rs` (file preamble, `Backend` impl), `naming.rs` (identifiers, types, `Dialect` marker), `expr.rs` (`ExprLang` impl, `store_value`), `decode.rs` / `encode.rs` (`StepEmitter` impls), `packet.rs` (struct + method wrappers), `json.rs` (`to_json`), `stream.rs` (`try_decode`, `frame_len`). Decoders take a `zero_copy` flag (`GenOptions::zero_copy`; `common::buffers` finds what holds byte buffers). Pascal adds `locals.rs`: every routine declares its locals in a `var` block, so the emitters collect them while writing the body. Its classes are declared in the interface and implemented after the runtime, which `runtime/pascal.pas` splits at its `@implementation` line. TypeScript adds `locals.rs` too: positions and window sizes are hoisted as `let`s at the top of each method. Lua's `expr.rs` only adds argument and constant spellings: both Lua generators share `common::lua` (one `ExprLang` for every `LuaDialect`, `store_value`, literals) and the runtime core `runtime/lua_core.lua` (reader, checksums, expression helpers), which `runtime/lua.lua` and `runtime/wireshark.lua` take in at their `-- @lua_core` line (`common::lua::runtime`). Fortran (2008) also has `locals.rs`; `runtime/fortran.f90` is split at its `! @contains` line into the module's declarations and procedures. Fortran has no exceptions, so every fallible call is followed by a check of the reader's or writer's `%e` and a return, and no unsigned integers, so `naming::int_kind` stores unsigned fields in the next wider kind. Ada (`src/generators/ada/`) follows the same plan: `locals.rs` collects each subprogram's declarations, `runtime/ada.ada` splits at `@implementation` into the package spec and body (one gnatchop-able file), and `types.rs` declares the records, variant records for unions, and controlled `<T>_Array` types that own packets through access values; `Boxes` puts by-value cycles (a packet holding itself through `at`) in one-element arrays. COBOL (GnuCOBOL, free format) also has `locals.rs` (LOCAL-STORAGE, since packet programs are RECURSIVE). Each packet is a fixed-size record (`naming.rs`) with programs `P<k>-<NAME>-INIT/-DEC/-ENC/-JSON/-FREE/-FRAME/-RUN` (`packet.rs`, `json.rs`, `stream.rs`). Runtime programs take their arguments in the EXTERNAL `PB-STATE` record, which `runtime/cobol.cob` keeps between `*>@state{` and `*>@state}` and `mod.rs` pastes at every program's `*>@STATE` line; every CALL is followed by an `IF PB-RC NOT = 0 GOBACK` check, and a packet program re-points `P-REC` (`SET ADDRESS OF P-REC TO PL-SELF`) after calling another one, because recursive calls share LINKAGE addresses. The main program (`main.rs`) reads the `.dat` file the harness writes (`!n` options are arguments of packets with parameters). |
| `src/generators/wireshark/` | the Wireshark Lua dissector generator (`dissector` command; not a `Language`): `naming.rs` (`WsLua` dialect, field keys; expressions come from `common::lua`), `fields.rs` (ProtoFields, value strings), `dissect.rs` (a decode `StepEmitter` that also fills the tree; failed checks become expert warnings), `mod.rs` (file layout, frame-length functions, registration). Runtime in `runtime/wireshark.lua` (plus the shared `runtime/lua_core.lua`). |
| `src/ir/views.rs` | `Module::add_views` (`generate --access`): for every member, a decode-only packet `<Packet>_<member>` whose steps skip what has a known size and read only what the skips and the member depend on. Backends need nothing special for it. `Module::elem_bits` gives the fixed size of one element of a codec. |
| `src/ir/frame.rs` | `Module::frame_length`: a packet's size from fixed-offset header fields, for TCP reassembly and stream framing. |
| `src/tools/` | `doc` (Markdown with bit diagrams), `fuzz` (cargo-fuzz / libFuzzer harnesses), `diff` (wire compatibility); CLI glue in `src/commands.rs`. |
| `runtime/` | hand-written runtime support pasted into each generated file. |
| `src/sources.rs`, `src/imports.rs` | `SourceMap` (every file gets a base offset, so a `Span` also says which file it is in; the parser adds the base) and the loader behind `compile_file`, which follows `import`s and merges the files' packets and constants. |
| `src/language.rs`, `src/lib.rs`, `src/main.rs` | `Language` enum, library entry points (`compile` for one source, `compile_file` with imports), CLI. |

## Design rules (SOLID / GoF)

The code is organised around a few traits. Reuse them instead of copying
code between backends.

- **Strategy + Factory** — `generators::Backend` is the interface of a code
  generator; `generators::backend(lang)` returns the one for a `Language`.
  Callers depend on the trait, not on concrete generators.
- **Template Method** — `common::StepEmitter` walks a packet's `Step`s and
  dispatches each to a hook (`align`, `calc`, `string`, `padding`, `scalar`,
  `array`, `bitfield`, `switch`, `open_window`/`close_window`,
  `open_gate`/`close_gate` (protocol versions), `at`, `check`). A position a
  gate contains is declared before it (`declare_mark`) and set inside it
  (`set_mark`), so a skipped field measures 0 bytes.
  Each backend's `Decoder` and `Encoder` only fill in the hooks; the
  dispatch lives in one place. Encoders keep the default `calc`. Before
  every field it calls `locate`, which records the field name for error
  paths. `emit_steps` also records the positions derived fields need
  (`mark`), then encoders patch derived fields (`define_local`,
  `write_derived`) and decoders verify them (`verify`).
- **Template Method** — `common::ConstEmitter` lays out a module's named
  constants (standalone ones, then each category); backends fill in
  `constant` and `category`, and it emits nothing for files without constants.
- **Visitor** — `common::emit_expr` walks a `TExpr` and asks an `ExprLang`
  implementation for each node's spelling.
- **Generic scope** — `common::Dialect` (boolean literals, how to name a
  member) is implemented by a zero-sized marker per language (`Rust`, `C`, ...);
  `common::Scope<'_, D>` provides `place()`, `field()`, `member()`,
  `expr()`, `param_var()` (parameters are `pbp_<name>` arguments of the
  generated functions) and `args()` (a nested packet's arguments) for all
  of them. Backends implement `ExprLang for Scope<'_, TheirDialect>`.
- **Builder** — `ir::analysis::packet::PacketBuilder` holds the per-packet
  analysis state; each pass is one method.
- Shared IR helpers (`Member::calc_expr`, `Member::is_calculated`,
  `Member::derived_expr`, `Packet::encode_calc_members`,
  `Packet::depends_on_wire`, `Packet::marks`) replace repeated `match`
  blocks; `common::union` holds the arm tests every backend's `switch` uses.

### Runtimes and errors

Every runtime (`runtime/*`) has the same shape: a reader and a writer that
keep a trace of frames (packet, field, array index). Generated code calls
`enter("Packet")` / `leave()` around a packet, `at("field")` before each
field and `at_index(i)` per array element; errors created by the runtime
capture the path, the bit offset and a kind (`incomplete`, `invalid`,
`range`, `text`, `mismatch`, `constraint`). `at` fields use reader
`jump`/`jump_back` and writer `sub`/`place`: a sub-writer's bytes are
written at their offset by the writer's `finish`, which top-level `encode`
calls. Running out of data is
`incomplete` only at the end of the real input; inside a reader window
(`push_limit`/`pop_limit`) it is `invalid`. Checks that can fail live on the
reader/writer so they can report the path. When adding a runtime function,
add it to all fourteen runtimes with the same semantics, and to the interpreter
if it changes what values mean. Code only files with protocol versions need
sits between `@versions{` and `@versions}` comment lines
(`common::runtime_source` drops it from other files).

When code is the same in two or more places, move it into `common/` (or onto
an IR type) behind a trait or helper. Keep files focused: one responsibility
per module, and split a file when it grows past roughly 400–500 lines.

### Adding a backend

1. Add a `Language` variant (`src/language.rs`) with its name and extension.
2. Create `src/generators/<lang>/` with the files above; implement
   `Dialect`, `ExprLang for Scope<'_, X>`, two `StepEmitter`s and `Backend`.
3. Register it in `generators::backend`.
4. Add a test harness in `tests/harness/<lang>.rs`. Drivers print two JSON
   lines per case (the decode/encode result, then what `try_decode` and
   `frame_len` say; see `tests/harness/mod.rs`), and every spec runs with
   and without `--zero-copy`.

### Adding a language feature

Add it to the grammar and AST, the analysis (a new `Step` or `Codec` where it
is on the wire), `layout.rs`, the interpreter, then every backend, and add
vectors to a `tests/specs/*.json` file; the interpreter target runs them
without any toolchain, which makes it the quickest check.

## Checks

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                # PB_REQUIRE_ALL=1 fails instead of skipping missing toolchains
```

`tests/wireshark.rs` runs every spec vector through tshark with the
generated dissector (skipped without tshark). Wireshark 4.6 crashes when a
Lua script rethrows an error raised by its API, so the Lua runtime never
rethrows: unexpected errors become "packet-builder internal error" expert
items, which the test treats as failures.

The codegen tests compile and run the generated code with each language's
toolchain (skipped when it is not installed). For refactors that should not
change output, generate every `examples/*.packet` and `tests/specs/*.packet`
before and after (`packet_builder generate <file> -o <dir>`) and diff the
results; they should be byte-identical.
