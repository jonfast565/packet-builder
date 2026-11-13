//! The main program: it reads the `.dat` file named on the command line
//! and runs each line through a packet's `-RUN` program (`stream.rs`).

use super::naming::{call, cob_literal};
use super::stream::ARGS_RECORD;
use crate::generators::common::Out;
use crate::ir::Module;

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
@RESET@
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
@ARGUMENT@
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

const ARGS_RESET: &str = "    MOVE 0 TO PB-ARGN\n";

const ARGS_OPTION: &str = r##"    *> `!N`: an argument of a packet with parameters.
    IF M-REC(M-TS:1) = "!"
        IF PB-ARGN >= 16
            MOVE 1 TO M-BAD
            MOVE "too many arguments" TO M-MSG
            EXIT PARAGRAPH
        END-IF
        COMPUTE M-I = M-TS + 1
        PERFORM M-DIGITS
        ADD 1 TO PB-ARGN
        MOVE M-W TO PB-ARG(PB-ARGN)
        EXIT PARAGRAPH
    END-IF
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
    // Arguments (`!n`) only matter to files with packets with parameters.
    let with_args = module.packets.iter().any(|p| !p.params.is_empty());
    if with_args {
        out.buf.push_str(ARGS_RECORD);
    }
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
        if !p.params.is_empty() {
            dispatch.open(format!("IF PB-ARGN NOT = {}", p.params.len()));
            dispatch.line("MOVE \"wrong number of arguments\" TO M-MSG");
            dispatch.line("PERFORM M-REJECT");
            dispatch.line("EXIT PARAGRAPH");
            dispatch.close("END-IF");
        }
        dispatch.line(format!("CALL {}", call(module, &p.name, "RUN")));
        dispatch.pop();
    }
    let (reset, argument) = if with_args { (ARGS_RESET, ARGS_OPTION) } else { ("", "") };
    let main = MAIN.replace("@RESET@\n", reset).replace("@ARGUMENT@\n", argument);
    out.buf.push_str(&main.replace("@PACKETS@\n", &dispatch.buf));
    out.line(format!("END PROGRAM {}.", name));
}
