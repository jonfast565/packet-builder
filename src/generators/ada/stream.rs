//! Stream helpers: `Try_Decode` (a packet, or how many more bytes are
//! needed) and `<T>_Frame_Len` (a packet's size from its header).

use super::decode::bits_value;
use super::expr::store_value;
use super::naming::{Ada, type_name};
use super::packet::version_param;
use crate::generators::common::{Dialect, Mode, Out, Scope};
use crate::ir::{Codec, Module, Packet};

fn try_header(p: &Packet) -> String {
    format!(
        "function Try_Decode (Data : Pb_Byte_Array; Value : out {}; Taken : out Integer_64{}) return Boolean",
        type_name(&p.name),
        version_param(p)
    )
}

fn frame_header(p: &Packet) -> String {
    format!("function {}_Frame_Len (Data : Pb_Byte_Array; Size : out Integer_64) return Boolean", type_name(&p.name))
}

pub fn declare_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    out.line("--  Decode from a buffer that may end mid-packet (a stream). True: Value and");
    out.line("--  the Taken bytes it took; False: at least Taken more bytes are needed.");
    out.line(format!("{};", try_header(p)));
    if let Some(f) = module.frame_length(p) {
        out.line(format!(
            "--  The packet's size from its first {} byte(s); False until they are there.",
            f.header_bytes
        ));
        out.line(format!("{};", frame_header(p)));
    }
}

/// The handler every public subprogram ends with: only Pb_Error escapes.
pub fn safety_net(out: &mut Out, name: &str) {
    out.line("exception");
    out.push();
    out.line("when Pb_Error =>");
    out.line("   raise;");
    out.line("when E : others =>");
    out.line("   Pb_Internal (E);");
    out.pop();
    out.line(format!("end {};", name));
}

/// `if Version /= 0 then ... end if;` for a reader or writer `rw`.
pub fn set_version(out: &mut Out, p: &Packet, rw: &str) {
    if p.versions.is_some() {
        let (min, latest) = p.version_bounds();
        out.line("if Version /= 0 then");
        out.line(format!("   Pb_Set_Version ({}.T, Version, {}, {});", rw, min, latest));
        out.line("end if;");
    }
}

pub fn implement_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    out.line("");
    out.line(format!("{} is", try_header(p)));
    out.line("begin");
    out.push();
    out.line("Taken := 0;");
    out.open("declare");
    out.line("Pb_Rd : aliased Pb_Reader (Data'Length);");
    out.close("begin");
    out.push();
    out.line("Pb_Init (Pb_Rd, Data);");
    set_version(out, p, "Pb_Rd");
    out.line("Value := Decode_From (Pb_Rd'Access);");
    out.line("Taken := (Pb_Rd.T.Pos + 7) / 8;");
    out.line("return True;");
    out.pop();
    out.line("exception");
    out.push();
    out.line("when Pb_Error =>");
    out.push();
    out.line("if Last_Error.Kind /= Pb_Incomplete then");
    out.line("   raise;");
    out.line("end if;");
    out.line("Taken := Integer_64'Max ((Last_Error.Needed_Bits + 7) / 8, 1);");
    out.line("return False;");
    out.pop();
    out.pop();
    out.line("end;");
    out.pop();
    safety_net(out, "Try_Decode");

    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<Ada>::new(p, Mode::Decode);
    out.line("");
    out.line(format!("{} is", frame_header(p)));
    out.line("begin");
    out.push();
    out.line("Size := 0;");
    if f.header_bytes > 0 {
        out.line(format!("if Data'Length < {} then", f.header_bytes));
        out.line("   return False;");
        out.line("end if;");
    }
    out.open("declare");
    out.line("Pb_Rd : aliased Pb_Reader (Data'Length);");
    out.line("R : constant not null access Pb_Reader := Pb_Rd'Access;");
    out.line(format!("P : {};", type_name(&p.name)));
    out.line("Pb_C : Unsigned_64;");
    out.line("Pb_N : Integer_64;");
    out.close("begin");
    out.push();
    for (fi, h) in f.fields.iter().enumerate() {
        let m = &p.members[h.member];
        // A field elsewhere in other protocol versions is read in its own.
        if let Some(c) = &h.when {
            out.open(format!("if {} then", scope.expr(c)));
        }
        out.line("Pb_Init (Pb_Rd, Data);");
        out.line(format!("Pb_Skip_Bits (R, {});", h.offset_bits));
        let raw = match &h.container {
            Codec::Bytes { nbytes, endian } => format!("Pb_Read_Uint (R, {}, {})", nbytes, Ada::little(endian)),
            _ => format!("Pb_Read_Bits (R, {})", h.container_bits),
        };
        out.line(format!("Pb_C := {};", raw));
        out.line(format!("{} := {};", scope.field(m), bits_value(&m.ty, "Pb_C", h.shift, h.bits, h.signed)));
        if h.when.is_some() {
            out.close("end if;");
        }
        // The rest of the header, once the version field says how long it is.
        if let (0, Some(need)) = (fi, &f.version_header) {
            out.line(format!("if Integer_64 (Data'Length) < {} then", scope.expr(need)));
            out.line("   return False;");
            out.line("end if;");
        }
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("{} := {};", scope.field(m), store_value(scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("Pb_N := {};", scope.expr(&f.total)));
    out.line("if Pb_N < 0 then");
    out.line("   Pb_Raise (Pb_Invalid, \"negative length \" & Pb_Img (Pb_N), \"\", 0);");
    out.line("end if;");
    out.line("Size := Pb_N;");
    out.line("return True;");
    out.pop();
    out.line("end;");
    out.pop();
    safety_net(out, &format!("{}_Frame_Len", type_name(&p.name)));
}
