//! The stream helpers and the driver programs.
//!
//! `-FRAME` is `frame_len`: a packet's size from its header (PB-FRC 0 and
//! PB-FLEN, 1 while the header is incomplete, 2 for a bad length). `-RUN`
//! runs one line of the `.dat` file the main program reads: decode the
//! bytes in PB-IN, apply the line's `path=value` settings, print the value
//! and the re-encoded bytes as one JSON line, then what `try_decode` and
//! `frame_len` say as a second line. Try-decoding is decoding: the reader
//! only reports `incomplete` at the end of the real input, with the bits
//! still needed.

use super::decode::little;
use super::expr::{Ev, store_value};
use super::json::disp;
use super::locals::{INT, Locals, body};
use super::naming::{
    call, cob_literal, declare_pointed, declare_record, field_name, member_offset, point, prog, record_size,
};
use super::packet::program;
use crate::generators::common::{Mode, Out};
use crate::ir::{Codec, Module, Packet, ValueType, storage_for};

/// The members a `.dat` line can set: scalar integers, floats and strings,
/// also inside nested packets (`table.first`), with their byte offsets.
fn settable(module: &Module, p: &Packet, prefix: &str, base: u64, depth: u32, out: &mut Vec<(String, u64, ValueType)>) {
    for (i, m) in p.members.iter().enumerate() {
        if m.array.is_some() {
            continue;
        }
        let off = base + member_offset(module, p, i);
        let path = format!("{}{}", prefix, m.name);
        match &m.ty {
            ValueType::Int { .. } | ValueType::Float { .. } | ValueType::Str => out.push((path, off, m.ty.clone())),
            ValueType::Packet(n) if depth < 3 => {
                let q = module.packets.iter().find(|q| &q.name == n).expect("packet exists");
                settable(module, q, &format!("{}.", path), off, depth + 1, out);
            }
            _ => {}
        }
    }
}

fn set_version(b: &mut Out, p: &Packet) {
    if p.versions.is_some() {
        let (min, latest) = p.version_bounds();
        b.open("IF PB-CVER NOT = 0");
        b.line("MOVE PB-CVER TO PB-A1");
        b.line(format!("MOVE {} TO PB-A2", min));
        b.line(format!("MOVE {} TO PB-A3", latest));
        b.line("CALL \"PB-SETVER\"");
        b.close("END-IF");
    }
}

fn run_program(out: &mut Out, module: &Module, p: &Packet) {
    let locals = Locals::default();
    locals.var("PL-K", INT);
    locals.var("PL-PTR", "USAGE POINTER");
    let dec = call(module, &p.name, "DEC");
    let free = call(module, &p.name, "FREE");
    let mut b = body();

    b.line("CALL \"PB-RINIT\"");
    set_version(&mut b, p);
    b.line(format!("IF PB-RC = 0 CALL {} USING P-REC END-IF", dec));
    b.open("IF PB-RC NOT = 0");
    disp(&mut b, "{\"ok\":false");
    b.line("MOVE 0 TO PB-A1");
    b.line("CALL \"PB-JERR\"");
    b.line("DISPLAY \"}\"");
    b.close("ELSE");
    b.push();
    let mut sets = Vec::new();
    settable(module, p, "", 0, 0, &mut sets);
    if !sets.is_empty() {
        b.open("PERFORM VARYING PL-K FROM 1 BY 1 UNTIL PL-K > PB-SETN");
        b.line("SET PL-PTR TO ADDRESS OF P-REC");
        b.open("EVALUATE PB-ST-PATH(PL-K)");
        for (path, off, ty) in &sets {
            b.open(format!("WHEN {}", cob_literal(path)));
            if *off > 0 {
                b.line(format!("SET PL-PTR UP BY {}", off));
            }
            let slot = point(&mut b, ty, "PL-PTR");
            match ty {
                ValueType::Int { width, signed } => {
                    let st = ValueType::Int { width: storage_for(*width), signed: *signed };
                    store_value(&mut b, "PB-ST-INT(PL-K)", &st, &slot.val);
                }
                ValueType::Str => {
                    b.line("IF LK-STR-P NOT = NULL FREE LK-STR-P END-IF");
                    b.line("SET PB-RP TO ADDRESS OF PB-ST-STR(PL-K)");
                    b.line("MOVE PB-ST-SLEN(PL-K) TO PB-RN");
                    b.line("CALL \"PB-DUP\"");
                    b.line("SET LK-STR-P TO PB-RP");
                    b.line("MOVE PB-RN TO LK-STR-N");
                }
                _ => b.line(format!("MOVE PB-ST-INT(PL-K) TO {}", slot.val)),
            }
            b.pop();
        }
        b.open("WHEN OTHER");
        b.line("CONTINUE");
        b.pop();
        b.close("END-EVALUATE");
        b.close("END-PERFORM");
    }
    disp(&mut b, "{\"ok\":true,\"value\":");
    b.line(format!("CALL {} USING P-REC", call(module, &p.name, "JSON")));
    b.line("CALL \"PB-WINIT\"");
    set_version(&mut b, p);
    b.line(format!("IF PB-RC = 0 CALL {} USING P-REC END-IF", call(module, &p.name, "ENC")));
    b.line("IF PB-RC = 0 CALL \"PB-WFINISH\" END-IF");
    b.open("IF PB-RC = 0");
    disp(&mut b, ",\"encoded\":");
    b.line("SET PB-WP TO ADDRESS OF PB-OUT");
    b.line("MOVE PB-WLEN TO PB-A1");
    b.line("CALL \"PB-JHEX\"");
    b.close("ELSE");
    b.push();
    b.line("MOVE 1 TO PB-A1");
    b.line("CALL \"PB-JERR\"");
    b.close("END-IF");
    b.line("DISPLAY \"}\"");
    b.close("END-IF");
    b.line(format!("CALL {} USING P-REC", free));

    b.line("CALL \"PB-RINIT\"");
    set_version(&mut b, p);
    b.line(format!("IF PB-RC = 0 CALL {} USING P-REC END-IF", dec));
    b.open("EVALUATE PB-RC");
    b.open("WHEN 0");
    disp(&mut b, "{\"try\":\"done\",\"n\":");
    b.line("COMPUTE PB-X = (PB-POS + 7) / 8");
    b.line("CALL \"PB-JI\"");
    b.pop();
    b.open("WHEN 1");
    disp(&mut b, "{\"try\":\"incomplete\",\"n\":");
    b.line("COMPUTE PB-X = (PB-ENEED + 7) / 8");
    b.line("IF PB-X < 1 MOVE 1 TO PB-X END-IF");
    b.line("CALL \"PB-JI\"");
    b.pop();
    b.open("WHEN OTHER");
    disp(&mut b, "{\"try\":\"error\"");
    b.pop();
    b.close("END-EVALUATE");
    b.line(format!("CALL {} USING P-REC", free));
    if module.frame_length(p).is_some() {
        b.line(format!("CALL {}", call(module, &p.name, "FRAME")));
        b.open("EVALUATE PB-FRC");
        b.open("WHEN 0");
        disp(&mut b, ",\"frame\":");
        b.line("MOVE PB-FLEN TO PB-X");
        b.line("CALL \"PB-JI\"");
        b.pop();
        b.open("WHEN 1");
        disp(&mut b, ",\"frame\":null");
        b.pop();
        b.open("WHEN OTHER");
        disp(&mut b, ",\"frame\":\"error\"");
        b.pop();
        b.close("END-EVALUATE");
    }
    b.line("DISPLAY \"}\"");
    b.line("GOBACK.");

    let storage = format!("01 P-REC PIC X({}).\n", record_size(module, &p.name));
    let mut linkage = Out::new("   ");
    declare_pointed(&mut linkage);
    program(out, &format!("{}-RUN", prog(module, &p.name)), false, &storage, &locals, &linkage.buf, "", b);
}

/// `-FRAME`: the size of the packet at the start of PB-IN from its header.
fn frame_program(out: &mut Out, module: &Module, p: &Packet) {
    let Some(f) = module.frame_length(p) else { return };
    let locals = Locals::default();
    let ev = Ev::new(module, p, Mode::Decode, &locals);
    let mut b = body();
    b.line("MOVE 1 TO PB-FRC");
    b.line("MOVE 0 TO PB-FLEN");
    if f.header_bytes > 0 {
        b.line(format!("IF PB-LEN < {} GOBACK END-IF", f.header_bytes));
    }
    b.line("MOVE LOW-VALUES TO P-REC");
    let bad = "IF PB-RC NOT = 0 MOVE 2 TO PB-FRC GOBACK END-IF";
    for (fi, h) in f.fields.iter().enumerate() {
        let m = &p.members[h.member];
        // A field elsewhere in other protocol versions is read in its own.
        if let Some(c) = &h.when {
            let v = ev.eval(&mut b, c);
            b.open(format!("IF {} NOT = 0", v));
        }
        b.line("CALL \"PB-RINIT\"");
        b.line(format!("MOVE {} TO PB-X", h.offset_bits));
        b.line("CALL \"PB-SKIP\"");
        b.line(bad);
        match &h.container {
            Codec::Bytes { nbytes, endian } => {
                b.line(format!("MOVE {} TO PB-A1", nbytes));
                b.line(format!("MOVE {} TO PB-A2", little(endian)));
                b.line("MOVE 0 TO PB-A3");
                b.line("CALL \"PB-RUINT\"");
            }
            _ => {
                b.line(format!("MOVE {} TO PB-A1", h.container_bits));
                b.line("MOVE 0 TO PB-A3");
                b.line("CALL \"PB-RBITS\"");
            }
        }
        b.line(bad);
        b.line("MOVE PB-Z TO PB-X");
        b.line(format!("MOVE {} TO PB-A1", h.shift));
        b.line(format!("MOVE {} TO PB-A2", h.bits));
        b.line(format!("MOVE {} TO PB-A3", u32::from(h.signed)));
        b.line("CALL \"PB-EXTRACT\"");
        b.line(format!("MOVE PB-Z TO {}", field_name(h.member, &m.name)));
        if h.when.is_some() {
            b.close("END-IF");
        }
        // The rest of the header, once the version field says how long it is.
        if let (0, Some(need)) = (fi, &f.version_header) {
            let v = ev.eval(&mut b, need);
            b.line(format!("IF PB-LEN < {} GOBACK END-IF", v));
        }
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            let v = ev.eval(&mut b, e);
            store_value(&mut b, &v, &m.ty, &field_name(c, &m.name));
        }
    }
    let total = ev.eval(&mut b, &f.total);
    b.line(format!("IF {} < 0 MOVE 2 TO PB-FRC GOBACK END-IF", total));
    b.line(format!("MOVE {} TO PB-FLEN", total));
    b.line("MOVE 0 TO PB-FRC");
    b.line("GOBACK.");

    let mut storage = Out::new("   ");
    declare_record(&mut storage, module, p, "P-REC");
    let mut linkage = Out::new("   ");
    declare_pointed(&mut linkage);
    program(out, &format!("{}-FRAME", prog(module, &p.name)), false, &storage.buf, &locals, &linkage.buf, "", b);
}

/// `-RUN` and `-FRAME` for packets without parameters.
pub fn stream_programs(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    frame_program(out, module, p);
    run_program(out, module, p);
}

/// The main program's procedures: read the `.dat` file named on the command
/// line (default `PACKETS.DAT`) and run each line; `@PACKETS@` is where the
/// dispatch on the packet name goes.
const MAIN: &str = r##"PROCEDURE DIVISION.
M-MAIN.
    CALL "PB-INIT"
    ACCEPT M-PATH FROM COMMAND-LINE
    IF M-PATH = SPACES
        MOVE "PACKETS.DAT" TO M-PATH
    END-IF
    OPEN INPUT PB-FILE
    IF M-FS NOT = "00"
        DISPLAY "cannot open " FUNCTION TRIM(M-PATH) UPON SYSERR
        MOVE 1 TO RETURN-CODE
        STOP RUN
    END-IF
    PERFORM UNTIL M-EOF = 1
        READ PB-FILE
            AT END MOVE 1 TO M-EOF
            NOT AT END PERFORM M-LINE
        END-READ
    END-PERFORM
    CLOSE PB-FILE
    STOP RUN.

*> One line: `<Packet> <hex or -> [@version] [path=integer | path=#hex]...`.
M-LINE.
    MOVE FUNCTION LENGTH(FUNCTION TRIM(M-REC TRAILING)) TO M-LEN
    IF M-LEN = 1 AND M-REC(1:1) = SPACE
        MOVE 0 TO M-LEN
    END-IF
    MOVE 1 TO M-P
    PERFORM M-TOKEN
    IF M-TL = 0
        EXIT PARAGRAPH
    END-IF
    IF M-REC(M-TS:1) = "*"
        EXIT PARAGRAPH
    END-IF
    MOVE SPACES TO M-NAME M-MSG
    IF M-TL > 64
        MOVE 64 TO M-TL
    END-IF
    MOVE M-REC(M-TS:M-TL) TO M-NAME
    MOVE 0 TO PB-LEN PB-SETN PB-CVER M-BAD
    PERFORM M-TOKEN
    IF M-TL = 0
        MOVE 1 TO M-BAD
        MOVE "missing bytes" TO M-MSG
    ELSE
        MOVE M-TS TO M-HS
        MOVE M-TL TO M-HL
        PERFORM M-HEX
        IF M-BLEN > 65536
            MOVE 1 TO M-BAD
            MOVE "more than 65536 bytes" TO M-MSG
        END-IF
        IF M-BAD = 0 AND M-BLEN > 0
            MOVE M-BUF(1:M-BLEN) TO PB-IN(1:M-BLEN)
        END-IF
        MOVE M-BLEN TO PB-LEN
    END-IF
    PERFORM M-TOKEN
    PERFORM UNTIL M-TL = 0 OR M-BAD NOT = 0
        PERFORM M-OPTION
        PERFORM M-TOKEN
    END-PERFORM
    IF M-BAD NOT = 0
        PERFORM M-REJECT
        EXIT PARAGRAPH
    END-IF
    EVALUATE M-NAME
@PACKETS@
        WHEN OTHER
            MOVE "unknown packet" TO M-MSG
            PERFORM M-REJECT
    END-EVALUATE.

M-REJECT.
    DISPLAY '{"ok":false,"error":"' FUNCTION TRIM(M-MSG) ': '
        FUNCTION TRIM(M-NAME) '","kind":"other","path":""}'
    DISPLAY '{"try":"error"}'.

*> The next blank-separated token: M-TS, M-TL (0 at the end).
M-TOKEN.
    PERFORM UNTIL M-P > M-LEN
        IF FUNCTION ORD(M-REC(M-P:1)) > 33
            EXIT PERFORM
        END-IF
        ADD 1 TO M-P
    END-PERFORM
    MOVE M-P TO M-TS
    PERFORM UNTIL M-P > M-LEN
        IF FUNCTION ORD(M-REC(M-P:1)) <= 33
            EXIT PERFORM
        END-IF
        ADD 1 TO M-P
    END-PERFORM
    COMPUTE M-TL = M-P - M-TS.

*> `-` (no bytes) or the hex digits at M-HS (M-HL long) into M-BUF, M-BLEN.
M-HEX.
    MOVE 0 TO M-BLEN
    IF M-HL = 1 AND M-REC(M-HS:1) = "-"
        EXIT PARAGRAPH
    END-IF
    DIVIDE M-HL BY 2 GIVING M-I REMAINDER M-D
    IF M-D NOT = 0 OR M-I > 70000
        MOVE 1 TO M-BAD
        MOVE "odd or too many hex digits" TO M-MSG
        EXIT PARAGRAPH
    END-IF
    PERFORM VARYING M-I FROM 0 BY 1 UNTIL M-I * 2 >= M-HL OR M-BAD NOT = 0
        COMPUTE M-C = FUNCTION ORD(M-REC(M-HS + M-I * 2:1))
        PERFORM M-NIBBLE
        COMPUTE M-H = M-D * 16
        COMPUTE M-C = FUNCTION ORD(M-REC(M-HS + M-I * 2 + 1:1))
        PERFORM M-NIBBLE
        COMPUTE M-BUFB(M-I + 1) = M-H + M-D
    END-PERFORM
    COMPUTE M-BLEN = M-HL / 2.

*> M-D := the value of hex digit M-C (an ORD: the code plus one).
M-NIBBLE.
    EVALUATE TRUE
        WHEN M-C >= 49 AND M-C <= 58
            COMPUTE M-D = M-C - 49
        WHEN M-C >= 98 AND M-C <= 103
            COMPUTE M-D = M-C - 88
        WHEN M-C >= 66 AND M-C <= 71
            COMPUTE M-D = M-C - 56
        WHEN OTHER
            MOVE 0 TO M-D
            MOVE 1 TO M-BAD
            MOVE "bad hex digit" TO M-MSG
    END-EVALUATE.

*> `@N` (the protocol version) or `path=value`.
M-OPTION.
    COMPUTE M-END = M-TS + M-TL
    IF M-REC(M-TS:1) = "@"
        COMPUTE M-I = M-TS + 1
        PERFORM M-DIGITS
        MOVE M-W TO PB-CVER
        EXIT PARAGRAPH
    END-IF
    MOVE 0 TO M-EQ
    PERFORM VARYING M-I FROM M-TS BY 1 UNTIL M-I >= M-END
        IF M-REC(M-I:1) = "="
            MOVE M-I TO M-EQ
            EXIT PERFORM
        END-IF
    END-PERFORM
    IF M-EQ <= M-TS OR M-EQ - M-TS > 128 OR PB-SETN >= 16
        MOVE 1 TO M-BAD
        MOVE "bad setting" TO M-MSG
        EXIT PARAGRAPH
    END-IF
    ADD 1 TO PB-SETN
    MOVE SPACES TO PB-ST-PATH(PB-SETN)
    MOVE M-REC(M-TS:M-EQ - M-TS) TO PB-ST-PATH(PB-SETN)
    COMPUTE M-I = M-EQ + 1
    IF M-I < M-END AND M-REC(M-I:1) = "#"
        COMPUTE M-HS = M-I + 1
        COMPUTE M-HL = M-END - M-HS
        PERFORM M-HEX
        IF M-BLEN > 4096
            MOVE 1 TO M-BAD
            MOVE "string longer than 4096 bytes" TO M-MSG
            EXIT PARAGRAPH
        END-IF
        MOVE 2 TO PB-ST-KIND(PB-SETN)
        MOVE M-BLEN TO PB-ST-SLEN(PB-SETN)
        IF M-BLEN > 0
            MOVE M-BUF(1:M-BLEN) TO PB-ST-STR(PB-SETN)(1:M-BLEN)
        END-IF
    ELSE
        PERFORM M-DIGITS
        MOVE M-W TO PB-W
        CALL "PB-WRAP"
        MOVE 1 TO PB-ST-KIND(PB-SETN)
        MOVE PB-Z TO PB-ST-INT(PB-SETN)
    END-IF.

*> M-W := the decimal integer from M-I to M-END.
M-DIGITS.
    MOVE 0 TO M-W M-NEG
    IF M-I < M-END AND M-REC(M-I:1) = "-"
        MOVE 1 TO M-NEG
        ADD 1 TO M-I
    END-IF
    IF M-I >= M-END
        MOVE 1 TO M-BAD
        MOVE "missing number" TO M-MSG
    END-IF
    PERFORM UNTIL M-I >= M-END OR M-BAD NOT = 0
        COMPUTE M-C = FUNCTION ORD(M-REC(M-I:1)) - 49
        IF M-C < 0 OR M-C > 9
            MOVE 1 TO M-BAD
            MOVE "bad number" TO M-MSG
        ELSE
            COMPUTE M-W = M-W * 10 + M-C
                ON SIZE ERROR
                    MOVE 1 TO M-BAD
                    MOVE "number too large" TO M-MSG
            END-COMPUTE
        END-IF
        ADD 1 TO M-I
    END-PERFORM
    IF M-NEG = 1
        COMPUTE M-W = 0 - M-W
    END-IF.
"##;

/// The main program (the first in the file, so `cobc -x` runs it).
pub fn main_program(out: &mut Out, module: &Module, name: &str) {
    out.line("IDENTIFICATION DIVISION.");
    out.line(format!("PROGRAM-ID. {}.", name));
    out.line("ENVIRONMENT DIVISION.");
    out.line("INPUT-OUTPUT SECTION.");
    out.line("FILE-CONTROL.");
    out.line("    SELECT PB-FILE ASSIGN TO DYNAMIC M-PATH");
    out.line("        ORGANIZATION IS LINE SEQUENTIAL");
    out.line("        FILE STATUS IS M-FS.");
    out.line("DATA DIVISION.");
    out.line("FILE SECTION.");
    out.line("FD PB-FILE.");
    out.line("01 M-REC PIC X(140000).");
    out.line("WORKING-STORAGE SECTION.");
    out.line("*>@STATE");
    out.line("01 M-PATH PIC X(1024).");
    out.line("01 M-FS PIC XX.");
    out.line("01 M-NAME PIC X(64).");
    out.line("01 M-MSG PIC X(64).");
    out.line("01 M-W PIC S9(38) COMP-3.");
    out.line("01 M-BUF PIC X(70000).");
    out.line("01 M-BUFA REDEFINES M-BUF.");
    out.line("   05 M-BUFB BINARY-CHAR UNSIGNED OCCURS 70000.");
    for v in [
        "M-EOF", "M-LEN", "M-P", "M-TS", "M-TL", "M-HS", "M-HL", "M-BLEN", "M-I", "M-EQ", "M-END", "M-C", "M-D", "M-H",
        "M-BAD", "M-NEG",
    ] {
        out.line(format!("01 {} BINARY-LONG SIGNED VALUE 0.", v));
    }
    let mut dispatch = Out::new("    ");
    dispatch.push();
    dispatch.push();
    for p in &module.packets {
        dispatch.line(format!("WHEN {}", cob_literal(&p.name)));
        dispatch.push();
        if p.params.is_empty() {
            dispatch.line(format!("CALL {}", call(module, &p.name, "RUN")));
        } else {
            dispatch.line("MOVE \"packet takes parameters\" TO M-MSG");
            dispatch.line("PERFORM M-REJECT");
        }
        dispatch.pop();
    }
    out.buf.push_str(&MAIN.replace("@PACKETS@\n", &dispatch.buf));
    out.line(format!("END PROGRAM {}.", name));
}
