//! Stream helpers: `TryDecode<P>` (a packet, or how many more bytes are
//! needed) and `FrameLen<P>` (a packet's size from its header).

use super::expr::store_value;
use super::naming::{Go, field_name, scalar_type};
use crate::generators::common::{Dialect, Mode, Out, Scope, mask};
use crate::ir::{Codec, Module, Packet};

pub fn emit_streaming(out: &mut Out, module: &Module, p: &Packet) {
    if !p.params.is_empty() {
        return;
    }
    let name = &p.name;
    out.line("");
    out.line(format!("// TryDecode{} decodes a {} from a buffer that may end mid-packet (a stream).", name, name));
    out.line("// It returns the packet and the bytes it took, or (nil, n, nil) when at least n");
    out.line("// more bytes are needed.");
    out.open(format!("func TryDecode{}(data []byte) (*{}, int, error) {{", name, name));
    out.line("pbR := NewPbReader(data)");
    out.line(format!("p := pbDecode{}(pbR)", name));
    out.open("if err := pbR.Err(); err != nil {");
    out.open("if e, ok := err.(*PbError); ok && e.Kind == PbIncomplete {");
    out.line("return nil, max((e.NeededBits+7)/8, 1), nil");
    out.close("}");
    out.line("return nil, 0, err");
    out.close("}");
    out.line("return &p, (pbR.PositionBits() + 7) / 8, nil");
    out.close("}");
    if p.versions.is_some() {
        let (min, latest) = p.version_bounds();
        out.line("");
        out.line(format!("// TryDecode{}V is TryDecode{} as protocol version version.", name, name));
        out.open(format!("func TryDecode{}V(data []byte, version int) (*{}, int, error) {{", name, name));
        out.line("pbR := NewPbReader(data)");
        out.line(format!("pbR.SetVersion(int64(version), {}, {})", min, latest));
        out.open("if err := pbR.Err(); err != nil {");
        out.line("return nil, 0, err");
        out.close("}");
        out.line(format!("p := pbDecode{}(pbR)", name));
        out.open("if err := pbR.Err(); err != nil {");
        out.open("if e, ok := err.(*PbError); ok && e.Kind == PbIncomplete {");
        out.line("return nil, max((e.NeededBits+7)/8, 1), nil");
        out.close("}");
        out.line("return nil, 0, err");
        out.close("}");
        out.line("return &p, (pbR.PositionBits() + 7) / 8, nil");
        out.close("}");
    }
    let Some(f) = module.frame_length(p) else { return };
    let scope = Scope::<Go>::new(p, Mode::Decode);
    out.line("");
    out.line(format!(
        "// FrameLen{} gives the size of the {} at the start of data from its first {} byte(s);",
        name, name, f.header_bytes
    ));
    out.line("// ok is false until they are there.");
    out.open(format!("func FrameLen{}(data []byte) (size int, ok bool, err error) {{", name));
    if f.header_bytes > 0 {
        out.open(format!("if len(data) < {} {{", f.header_bytes));
        out.line("return 0, false, nil");
        out.close("}");
    }
    if !f.fields.is_empty() || !f.calcs.is_empty() {
        out.line(format!("var p {}", name));
    }
    for h in &f.fields {
        let m = &p.members[h.member];
        out.open("{");
        out.line("pbR := NewPbReader(data)");
        out.line(format!("pbR.SkipBits({})", h.offset_bits));
        let raw = match &h.container {
            Codec::Bytes { nbytes, endian } => format!("pbR.ReadUint({}, {})", nbytes, Go::little(endian)),
            _ => format!("pbR.ReadBits({})", h.container_bits),
        };
        out.line(format!("pbC := {}", raw));
        let bits = format!("((pbC >> {}) & 0x{:x})", h.shift, mask(h.bits));
        let st = scalar_type(&m.ty);
        let v = if h.signed { format!("{}(pbSext({}, {}))", st, bits, h.bits) } else { format!("{}({})", st, bits) };
        out.line(format!("p.{} = {}", field_name(&m.name), v));
        out.close("}");
    }
    for &c in &f.calcs {
        let m = &p.members[c];
        if let Some(e) = m.calc_expr() {
            out.line(format!("p.{} = {}", field_name(&m.name), store_value(e, scope.expr(e), &m.ty)));
        }
    }
    out.line(format!("pbN := {}", scope.expr(&f.total)));
    out.open("if pbN < 0 {");
    out.line("return 0, false, &PbError{Kind: PbInvalid, Msg: fmt.Sprintf(\"negative length %d\", pbN)}");
    out.close("}");
    out.line("return int(pbN), true, nil");
    out.close("}");
}
