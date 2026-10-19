//! Semantic analysis: turns the parsed packet list into a validated,
//! language-independent layout that every code generator consumes.
//!
//! The analysis
//! - resolves packet references and rejects cycles,
//! - tracks the bit offset of every field so that byte-oriented types are
//!   only used where they are byte aligned,
//! - type-checks expressions (integer / float / boolean),
//! - decides when each calculated field can be evaluated while decoding.

use std::collections::{HashMap, HashSet};

use crate::errors::Diagnostic;
use crate::models::parsing_models::{
    ArrayLength, BitOrder, Endianness, ExprNode, PacketExpr, PacketExprList, PacketItem, Span, TypeNode,
};

#[derive(Debug, Clone)]
pub struct Module {
    pub packets: Vec<Packet>,
}

impl Module {
    /// Packets ordered so that every packet comes after the packets it
    /// contains (needed by languages that require declaration before use).
    pub fn in_dependency_order(&self) -> Vec<&Packet> {
        fn visit<'a>(m: &'a Module, p: &'a Packet, seen: &mut HashSet<String>, out: &mut Vec<&'a Packet>) {
            if !seen.insert(p.name.clone()) {
                return;
            }
            for member in &p.members {
                if let ValueType::Packet(n) = &member.ty
                    && let Some(dep) = m.packets.iter().find(|x| &x.name == n)
                {
                    visit(m, dep, seen, out);
                }
            }
            out.push(p);
        }
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for p in &self.packets {
            visit(self, p, &mut seen, &mut out);
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub name: String,
    /// Struct members in declaration order (stored fields, bitfield members,
    /// calculated fields). Padding is not a member.
    pub members: Vec<Member>,
    /// Wire steps in order. Encoding walks the same list and skips `Calc`.
    pub steps: Vec<Step>,
    /// Calculated members that encoding needs (because a length depends on
    /// them), in an order where dependencies come first.
    pub encode_calcs: Vec<usize>,
    /// Smallest possible encoded size in bits.
    pub min_bits: u64,
    /// True if the last field consumes the rest of the input.
    pub open_ended: bool,
    /// Encoded size in bits when it does not depend on the data.
    pub fixed_bits: Option<u64>,
    /// Alignment in bytes of the packet when nested (from `packet P align N`).
    pub alignment: u64,
}

impl Packet {
    /// True if decoding/encoding needs the packet's start position.
    pub fn uses_align(&self) -> bool {
        self.steps.iter().any(|s| matches!(s, Step::Align { .. }))
    }
}

#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub ty: ValueType,
    pub array: Option<Count>,
    pub kind: MemberKind,
}

#[derive(Debug, Clone)]
pub enum MemberKind {
    Stored,
    BitfieldPart,
    Calculated(TExpr),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ValueType {
    /// Integer with a logical width of 1..=64 bits.
    Int { width: u32, signed: bool },
    /// IEEE float, 32 or 64 bits.
    Float { width: u32 },
    /// 6-byte hardware address.
    Mac,
    /// Another packet.
    Packet(String),
    /// Text (UTF-8).
    Str,
}

impl ValueType {
    /// Width of the native integer used to hold the value (8/16/32/64).
    pub fn storage_bits(&self) -> u32 {
        match self {
            ValueType::Int { width, .. } => storage_for(*width),
            ValueType::Float { width } => *width,
            ValueType::Mac => 48,
            ValueType::Packet(_) | ValueType::Str => 0,
        }
    }

    pub fn is_signed(&self) -> bool {
        matches!(self, ValueType::Int { signed: true, .. })
    }

    /// Unsigned 8-bit values; arrays of them are represented as byte buffers.
    pub fn is_byte(&self) -> bool {
        matches!(self, ValueType::Int { width: 8, signed: false })
    }

    /// True if the logical width is narrower than the storage type, so values
    /// must be range-checked before encoding.
    pub fn needs_range_check(&self) -> bool {
        match self {
            ValueType::Int { width, .. } => *width != storage_for(*width),
            _ => false,
        }
    }
}

pub fn storage_for(width: u32) -> u32 {
    match width {
        0..=8 => 8,
        9..=16 => 16,
        17..=32 => 32,
        _ => 64,
    }
}

#[derive(Debug, Clone)]
pub enum Count {
    Expr(TExpr),
    /// Repeat until the input is exhausted.
    Remaining,
}

/// How a single element travels on the wire.
#[derive(Debug, Clone, PartialEq)]
pub enum Codec {
    /// Byte aligned integer of `nbytes` bytes in the given byte order.
    Bytes {
        nbytes: u32,
        endian: Endianness,
    },
    /// Integer of `width` bits read MSB-first from the bit stream.
    Bits {
        width: u32,
    },
    Float {
        width: u32,
        endian: Endianness,
    },
    Mac,
    Packet(String),
    Str(StrMode),
}

/// How a string's length is determined. For `Padded` and `Exact` the byte
/// count is the step's `array` count.
#[derive(Debug, Clone, PartialEq)]
pub enum StrMode {
    /// `char[n]`: n bytes; the text ends at the first NUL, encoding pads with NULs.
    Padded,
    /// `string[n]` / `string[]`: exactly the given bytes.
    Exact,
    /// `string(uint8)`: a length prefix (written automatically), then the bytes.
    Prefixed { prefix: Box<Codec>, width: u32 },
    /// `cstring`: bytes up to a terminating NUL.
    CString,
}

impl Codec {
    pub fn bits(&self) -> u32 {
        match self {
            Codec::Bytes { nbytes, .. } => nbytes * 8,
            Codec::Bits { width } => *width,
            Codec::Float { width, .. } => *width,
            Codec::Mac => 48,
            Codec::Packet(_) | Codec::Str(_) => 0,
        }
    }

    /// Lower bound on the size of one element, used to reject element counts
    /// larger than the remaining input before allocating. Nested packets in
    /// arrays are at least one byte (enforced by the analysis).
    pub fn min_elem_bits(&self) -> u64 {
        match self {
            Codec::Packet(_) | Codec::Str(_) => 8,
            c => c.bits() as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Step {
    /// A stored member, or padding when `member` is None.
    Field { member: Option<usize>, ty: ValueType, codec: Codec, array: Option<Count> },
    /// An integer container split into sub-fields.
    Bitfield { container: Codec, container_width: u32, parts: Vec<BitPart> },
    /// Evaluate a calculated member (decode only).
    Calc { member: usize },
    /// Skip (decode) or zero-fill (encode) to the next multiple of `bytes`
    /// bytes counted from the start of the packet.
    Align { bytes: u64 },
}

#[derive(Debug, Clone)]
pub struct BitPart {
    pub member: usize,
    pub shift: u32,
    pub width: u32,
    pub signed: bool,
}

// ---------------------------------------------------------------------------
// Typed expressions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Int,
    Float,
    Bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Pow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
    Ne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicOp {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggOp {
    Sum,
    Product,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Func {
    Sqrt,
    Min,
    Max,
}

/// A type-checked expression. Integer arithmetic is 64-bit two's complement
/// (wrapping); integer division truncates toward zero and yields 0 when
/// dividing by zero; out-of-range array indexes yield 0. Every backend
/// implements exactly these semantics.
#[derive(Debug, Clone, PartialEq)]
pub enum TExpr {
    IntLit(i64),
    FloatLit(f64),
    /// Scalar member converted to i64 / f64.
    Ref {
        member: usize,
        ty: Ty,
    },
    /// Element of an array member.
    Index {
        member: usize,
        index: Box<TExpr>,
        ty: Ty,
    },
    Aggregate {
        member: usize,
        op: AggOp,
        ty: Ty,
    },
    Arith {
        op: ArithOp,
        a: Box<TExpr>,
        b: Box<TExpr>,
        ty: Ty,
    },
    Cmp {
        op: CmpOp,
        a: Box<TExpr>,
        b: Box<TExpr>,
    },
    Logic {
        op: LogicOp,
        a: Box<TExpr>,
        b: Box<TExpr>,
    },
    Guard {
        cond: Box<TExpr>,
        then: Box<TExpr>,
        other: Box<TExpr>,
        ty: Ty,
    },
    Call {
        func: Func,
        args: Vec<TExpr>,
        ty: Ty,
    },
    Convert {
        e: Box<TExpr>,
        to: Ty,
    },
}

impl TExpr {
    pub fn ty(&self) -> Ty {
        match self {
            TExpr::IntLit(_) => Ty::Int,
            TExpr::FloatLit(_) => Ty::Float,
            TExpr::Ref { ty, .. }
            | TExpr::Index { ty, .. }
            | TExpr::Aggregate { ty, .. }
            | TExpr::Arith { ty, .. }
            | TExpr::Guard { ty, .. }
            | TExpr::Call { ty, .. } => *ty,
            TExpr::Cmp { .. } | TExpr::Logic { .. } => Ty::Bool,
            TExpr::Convert { to, .. } => *to,
        }
    }

    /// Members this expression reads.
    pub fn deps(&self, out: &mut Vec<usize>) {
        match self {
            TExpr::IntLit(_) | TExpr::FloatLit(_) => {}
            TExpr::Ref { member, .. } | TExpr::Aggregate { member, .. } => out.push(*member),
            TExpr::Index { member, index, .. } => {
                out.push(*member);
                index.deps(out);
            }
            TExpr::Arith { a, b, .. } | TExpr::Cmp { a, b, .. } | TExpr::Logic { a, b, .. } => {
                a.deps(out);
                b.deps(out);
            }
            TExpr::Guard { cond, then, other, .. } => {
                cond.deps(out);
                then.deps(out);
                other.deps(out);
            }
            TExpr::Call { args, .. } => args.iter().for_each(|a| a.deps(out)),
            TExpr::Convert { e, .. } => e.deps(out),
        }
    }

    /// Value of an integer expression made only of literals.
    pub fn const_int(&self) -> Option<i64> {
        match self {
            TExpr::IntLit(v) => Some(*v),
            TExpr::Arith { op, a, b, ty: Ty::Int } => {
                let (a, b) = (a.const_int()?, b.const_int()?);
                Some(match op {
                    ArithOp::Add => a.wrapping_add(b),
                    ArithOp::Sub => a.wrapping_sub(b),
                    ArithOp::Mul => a.wrapping_mul(b),
                    ArithOp::Div => {
                        if b == 0 {
                            0
                        } else {
                            a.wrapping_div(b)
                        }
                    }
                    ArithOp::Pow => {
                        if b < 0 {
                            0
                        } else {
                            a.wrapping_pow(b.min(u32::MAX as i64) as u32)
                        }
                    }
                })
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

pub fn analyze(list: &PacketExprList) -> Result<Module, Vec<Diagnostic>> {
    let mut diags = Vec::new();

    // Packet names
    let mut by_name = HashMap::<String, usize>::new();
    const BUILTIN: &[&str] = &[
        "int8",
        "uint8",
        "int16",
        "uint16",
        "int32",
        "uint32",
        "int64",
        "uint64",
        "float32",
        "float64",
        "macaddress",
        "datetime",
        "bytes",
        "char",
        "uchar",
        "byte",
        "short",
        "ushort",
        "int",
        "uint",
        "halfword",
        "word",
        "dword",
        "doubleword",
        "qword",
        "quadword",
        "string",
        "cstring",
    ];
    for (i, p) in list.packets.iter().enumerate() {
        let looks_like_bits = p.name.len() > 1
            && (p.name.starts_with('u') || p.name.starts_with('i'))
            && p.name[1..].chars().all(|c| c.is_ascii_digit());
        if BUILTIN.contains(&p.name.as_str()) || looks_like_bits {
            diags.push(Diagnostic::new(format!("packet name `{}` is a built-in type name", p.name), p.span));
        }
        if by_name.insert(p.name.clone(), i).is_some() {
            diags.push(Diagnostic::new(format!("packet `{}` is declared more than once", p.name), p.span));
        }
    }

    // Dependency order between packets (nested packets first), rejecting cycles.
    let order = match packet_order(list, &by_name) {
        Ok(o) => o,
        Err(d) => {
            diags.extend(d);
            return Err(diags);
        }
    };

    let mut done = HashMap::<String, Packet>::new();
    for idx in order {
        let p = &list.packets[idx];
        match analyze_packet(p, &done) {
            Ok(packet) => {
                done.insert(packet.name.clone(), packet);
            }
            Err(d) => diags.extend(d),
        }
    }

    if !diags.is_empty() {
        return Err(diags);
    }

    let packets = list.packets.iter().map(|p| done.remove(&p.name).expect("analyzed")).collect();
    Ok(Module { packets })
}

fn packet_order(list: &PacketExprList, by_name: &HashMap<String, usize>) -> Result<Vec<usize>, Vec<Diagnostic>> {
    let mut diags = Vec::new();
    let mut state = vec![0u8; list.packets.len()]; // 0 = new, 1 = visiting, 2 = done
    let mut order = Vec::new();

    fn visit(
        i: usize,
        list: &PacketExprList,
        by_name: &HashMap<String, usize>,
        state: &mut Vec<u8>,
        order: &mut Vec<usize>,
        diags: &mut Vec<Diagnostic>,
    ) {
        if state[i] == 2 {
            return;
        }
        if state[i] == 1 {
            diags.push(Diagnostic::new(
                format!("packet `{}` contains itself", list.packets[i].name),
                list.packets[i].span,
            ));
            return;
        }
        state[i] = 1;
        for item in &list.packets[i].items {
            if let PacketItem::Field(f) = item
                && let TypeNode::Packet(name) = &f.expr
            {
                match by_name.get(name) {
                        Some(j) => visit(*j, list, by_name, state, order, diags),
                        None => diags.push(Diagnostic::new(format!("unknown type `{}`", name), f.span).with_note(
                            "built-in types are uint8..uint64, int8..int64, uN/iN, float32, float64, macaddress, datetime, bytes",
                        )),
                    }
            }
        }
        state[i] = 2;
        order.push(i);
    }

    for i in 0..list.packets.len() {
        visit(i, list, by_name, &mut state, &mut order, &mut diags);
    }
    if diags.is_empty() { Ok(order) } else { Err(diags) }
}

fn value_type(t: &TypeNode) -> ValueType {
    match t {
        TypeNode::Str | TypeNode::CStr | TypeNode::PrefixedStr { .. } => ValueType::Str,
        TypeNode::Float32 => ValueType::Float { width: 32 },
        TypeNode::Float64 => ValueType::Float { width: 64 },
        TypeNode::MacAddress => ValueType::Mac,
        TypeNode::Packet(n) => ValueType::Packet(n.clone()),
        other => {
            let (width, signed) = other.integer_info().expect("integer type");
            ValueType::Int { width, signed }
        }
    }
}

fn type_label(t: &TypeNode) -> String {
    match t {
        TypeNode::Integer8 => "int8".into(),
        TypeNode::UnsignedInteger8 => "uint8".into(),
        TypeNode::Integer16 => "int16".into(),
        TypeNode::UnsignedInteger16 => "uint16".into(),
        TypeNode::Integer32 => "int32".into(),
        TypeNode::UnsignedInteger32 => "uint32".into(),
        TypeNode::Integer64 => "int64".into(),
        TypeNode::UnsignedInteger64 => "uint64".into(),
        TypeNode::Float32 => "float32".into(),
        TypeNode::Float64 => "float64".into(),
        TypeNode::MacAddress => "macaddress".into(),
        TypeNode::DateTime => "datetime".into(),
        TypeNode::Bytes => "bytes".into(),
        TypeNode::Bits { width, signed } => format!("{}{}", if *signed { "i" } else { "u" }, width),
        TypeNode::Packet(n) => n.clone(),
        TypeNode::Char => "char".into(),
        TypeNode::Str => "string".into(),
        TypeNode::CStr => "cstring".into(),
        TypeNode::PrefixedStr { prefix, .. } => format!("string({})", type_label(prefix)),
    }
}

/// Value type of a declared field: `char[n]` is a string.
fn field_value_type(f: &crate::models::parsing_models::TypeExpr) -> ValueType {
    if f.expr == TypeNode::Char && f.array.is_some() { ValueType::Str } else { value_type(&f.expr) }
}

/// Natural alignment in bytes of a type, as a C compiler would lay it out.
fn natural_align(t: &TypeNode, done: &HashMap<String, Packet>) -> u64 {
    match t {
        TypeNode::Packet(n) => done.get(n).map(|p| p.alignment).unwrap_or(1),
        TypeNode::Bits { width, .. } => {
            let bytes = (*width / 8) as u64;
            if width % 8 == 0 && bytes.is_power_of_two() { bytes } else { 1 }
        }
        TypeNode::MacAddress | TypeNode::Bytes | TypeNode::Char | TypeNode::Str | TypeNode::CStr => 1,
        TypeNode::PrefixedStr { prefix, .. } => natural_align(prefix, done),
        other => other.bit_width().map(|b| (b / 8) as u64).unwrap_or(1),
    }
}

/// Insert an alignment step unless the offset is known to be aligned already.
fn emit_align(bytes: u64, steps: &mut Vec<Step>, align: &mut Align, exact: &mut Option<u64>, min_bits: &mut u64) {
    if bytes <= 1 && align.is_aligned() {
        return;
    }
    let bits = bytes * 8;
    if let Some(x) = *exact {
        let pad = (bits - x % bits) % bits;
        if pad == 0 {
            return;
        }
        *exact = Some(x + pad);
        *min_bits += pad;
    }
    steps.push(Step::Align { bytes });
    *align = Align::START;
}

/// What is known about the current bit offset: it is congruent to `offset`
/// modulo `modulus` (a divisor of 8). Byte aligned means `offset == 0` with
/// `modulus == 8`; variable-length arrays of bit-sized elements weaken the
/// modulus (e.g. `u12[n]` leaves the offset known only modulo 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Align {
    offset: u32,
    modulus: u32,
}

impl Align {
    const START: Align = Align { offset: 0, modulus: 8 };

    fn is_aligned(&self) -> bool {
        self.modulus == 8 && self.offset == 0
    }

    /// Advance by a fixed number of bits.
    fn advance(self, bits: u64) -> Align {
        Align { offset: ((self.offset as u64 + bits) % self.modulus as u64) as u32, modulus: self.modulus }
    }

    /// Advance by an unknown multiple of `step` bits.
    fn advance_multiple(self, step: u64) -> Align {
        let modulus = gcd(self.modulus as u64, step) as u32;
        Align { offset: self.offset % modulus, modulus }
    }

    fn describe(&self) -> String {
        if self.modulus == 8 {
            format!("{} bit(s) into a byte", self.offset)
        } else {
            "at a bit offset that depends on the data".to_string()
        }
    }
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// A constant factor of an integer expression (`n * 2` → 2), 1 if unknown.
fn const_factor(e: &TExpr) -> u64 {
    match e {
        TExpr::IntLit(v) => v.unsigned_abs(),
        TExpr::Arith { op: ArithOp::Mul, a, b, .. } => const_factor(a).wrapping_mul(const_factor(b)),
        TExpr::Convert { e, .. } => const_factor(e),
        _ => 1,
    }
}

struct Ctx<'a> {
    packet: &'a PacketExpr,
    done: &'a HashMap<String, Packet>,
    members: Vec<Member>,
    names: HashMap<String, usize>,
    diags: Vec<Diagnostic>,
}

fn analyze_packet(p: &PacketExpr, done: &HashMap<String, Packet>) -> Result<Packet, Vec<Diagnostic>> {
    let mut ctx = Ctx { packet: p, done, members: Vec::new(), names: HashMap::new(), diags: Vec::new() };
    let default_endian = p.endianness.clone().unwrap_or(Endianness::Le);

    // Pass 1: declare every member so expressions can refer to any of them.
    for item in &p.items {
        match item {
            PacketItem::Field(f) => {
                if f.id == "_" {
                    continue;
                }
                ctx.declare(&f.id, field_value_type(f), MemberKind::Stored, f.span);
            }
            PacketItem::Bitfield(b) => {
                for m in &b.members {
                    if m.name == "_" {
                        continue;
                    }
                    ctx.declare(
                        &m.name,
                        ValueType::Int { width: m.width, signed: m.signed },
                        MemberKind::BitfieldPart,
                        m.span,
                    );
                }
            }
            PacketItem::Calculated(c) => {
                let ty = match &c.data_type {
                    TypeNode::MacAddress
                    | TypeNode::Bytes
                    | TypeNode::Packet(_)
                    | TypeNode::Str
                    | TypeNode::CStr
                    | TypeNode::PrefixedStr { .. } => {
                        ctx.diags.push(Diagnostic::new(
                            format!("calculated field `{}` must have a numeric type", c.name),
                            c.span,
                        ));
                        ValueType::Int { width: 64, signed: true }
                    }
                    t => value_type(t),
                };
                ctx.declare(&c.name, ty, MemberKind::Calculated(TExpr::IntLit(0)), c.span);
            }
            PacketItem::Align(..) => {}
        }
    }

    // Pass 2: array counts (need the full name table).
    let mut field_counts = Vec::<Option<Count>>::new();
    for item in &p.items {
        if let PacketItem::Field(f) = item {
            let count = match &f.array {
                None => None,
                Some(ArrayLength::Remaining) => Some(Count::Remaining),
                Some(ArrayLength::Expr(e)) => ctx.check_expr(e, f.span).map(|t| Count::Expr(coerce(t, Ty::Int))),
            };
            if let Some(&idx) = ctx.names.get(&f.id)
                && f.id != "_"
                && field_value_type(f) != ValueType::Str
            {
                ctx.members[idx].array = count.clone();
            }
            field_counts.push(count);
        }
    }

    // Pass 3: calculated field expressions.
    for item in &p.items {
        if let PacketItem::Calculated(c) = item
            && let Some(t) = ctx.check_expr(&c.expr, c.span)
        {
            let idx = ctx.names[&c.name];
            let target = match ctx.members[idx].ty {
                ValueType::Float { .. } => Ty::Float,
                _ => Ty::Int,
            };
            ctx.members[idx].kind = MemberKind::Calculated(coerce(t, target));
        }
    }

    // Pass 4: layout, alignment and decode order.
    let mut steps = Vec::<Step>::new();
    let mut available = HashSet::<usize>::new();
    let mut scheduled = HashSet::<usize>::new();
    let mut align = Align::START;
    let mut min_bits: u64 = 0;
    let mut open_ended = false;
    let mut field_no = 0usize;
    // Exact bit offset from the packet start while it does not depend on data.
    let mut exact: Option<u64> = Some(0);
    // Alignment of this packet when nested (C struct rules under `align N`).
    let mut alignment: u64 = 1;
    // Padding requested before a field: its explicit `align N`, and under
    // `packet P align N` its natural alignment. None when nothing applies, so
    // that packed bit fields are left alone.
    let natural = |t: &TypeNode, explicit: Option<u64>, alignment: &mut u64| -> Option<u64> {
        let mut a = explicit;
        if let Some(pack) = p.align {
            let n = natural_align(t, done).min(pack).max(1);
            *alignment = (*alignment).max(n);
            if n > 1 {
                a = Some(a.unwrap_or(1).max(n));
            }
        }
        a
    };
    let stored_items: Vec<usize> = p
        .items
        .iter()
        .enumerate()
        .filter(|(_, it)| matches!(it, PacketItem::Field(_) | PacketItem::Bitfield(_)))
        .map(|(i, _)| i)
        .collect();
    let last_stored = stored_items.last().copied();

    ctx.schedule_calcs(&mut steps, &available, &mut scheduled);

    for (item_idx, item) in p.items.iter().enumerate() {
        match item {
            PacketItem::Calculated(_) => {}
            PacketItem::Align(bytes, span) => {
                if open_ended {
                    ctx.diags
                        .push(Diagnostic::new("`align` follows a field that consumes the rest of the input", *span));
                }
                emit_align(*bytes, &mut steps, &mut align, &mut exact, &mut min_bits);
            }
            PacketItem::Field(f) => {
                let count = field_counts[field_no].clone();
                field_no += 1;
                let is_last = Some(item_idx) == last_stored;
                let member = if f.id == "_" { None } else { ctx.names.get(&f.id).copied() };
                let ty = field_value_type(f);
                if let Some(pad) = natural(&f.expr, f.align, &mut alignment) {
                    emit_align(pad, &mut steps, &mut align, &mut exact, &mut min_bits);
                }

                if open_ended {
                    ctx.diags.push(Diagnostic::new(
                        format!("field `{}` follows a field that consumes the rest of the input", f.id),
                        f.span,
                    ));
                }

                // Lengths must only use values already decoded.
                if let Some(Count::Expr(e)) = &count {
                    ctx.require_available(e, &available, &scheduled, f.span, &f.id);
                }
                if matches!(count, Some(Count::Remaining)) {
                    if !is_last {
                        ctx.diags.push(
                            Diagnostic::new(
                                format!("`{}` has no length, so it must be the last field of `{}`", f.id, p.name),
                                f.span,
                            )
                            .with_note("give it a length such as bytes[len], or move it to the end"),
                        );
                    }
                    open_ended = true;
                }

                if f.id == "_" && !matches!(ty, ValueType::Int { .. }) {
                    ctx.diags.push(Diagnostic::new("padding (`_`) must have an integer or bytes type", f.span));
                }

                if let ValueType::Packet(name) = &ty {
                    if f.endianness.is_some() {
                        ctx.diags.push(Diagnostic::new(
                            format!("endianness on `{}` has no effect; set it on packet `{}` instead", f.id, name),
                            f.span,
                        ));
                    }
                    if let Some(nested) = ctx.done.get(name) {
                        if nested.open_ended && (!is_last || count.is_some()) {
                            ctx.diags.push(Diagnostic::new(
                                format!(
                                    "packet `{}` consumes the rest of the input, so `{}` must be a single, last field",
                                    name, f.id
                                ),
                                f.span,
                            ));
                        }
                        if nested.open_ended {
                            open_ended = true;
                        }
                        if count.is_some() && nested.min_bits < 8 {
                            ctx.diags.push(Diagnostic::new(
                                format!("packet `{}` can be empty, so it cannot be used in the array `{}`", name, f.id),
                                f.span,
                            ));
                        }
                    }
                }

                let codec = if ty == ValueType::Str {
                    ctx.string_codec(f, &default_endian, align)
                } else {
                    ctx.codec_for(&f.expr, f.endianness.clone(), &default_endian, align, f.span, &f.id)
                };
                let (elem_bits, elem_fixed) = match &codec {
                    Codec::Packet(n) => {
                        let nested = ctx.done.get(n);
                        (nested.map(|x| x.min_bits).unwrap_or(0), nested.and_then(|x| x.fixed_bits))
                    }
                    Codec::Str(StrMode::Padded | StrMode::Exact) => (8, Some(8)),
                    Codec::Str(StrMode::Prefixed { width, .. }) => (*width as u64, None),
                    Codec::Str(StrMode::CString) => (8, None),
                    c => (c.bits() as u64, Some(c.bits() as u64)),
                };
                // Advance alignment and the exact offset.
                match &count {
                    None => {
                        min_bits += elem_bits;
                        align = align.advance(elem_bits);
                        exact = exact.and_then(|x| elem_fixed.map(|b| x + b));
                    }
                    Some(Count::Expr(e)) => match e.const_int() {
                        Some(n) if n >= 0 => {
                            min_bits += elem_bits * n as u64;
                            align = align.advance(elem_bits.wrapping_mul(n as u64));
                            exact = exact.and_then(|x| elem_fixed.map(|b| x + b * n as u64));
                        }
                        _ => {
                            align = align.advance_multiple(elem_bits.wrapping_mul(const_factor(e)));
                            exact = None;
                        }
                    },
                    Some(Count::Remaining) => {
                        align = align.advance_multiple(elem_bits);
                        exact = None;
                    }
                }

                steps.push(Step::Field { member, ty, codec, array: count });
                if let Some(m) = member {
                    available.insert(m);
                }
            }
            PacketItem::Bitfield(b) => {
                if open_ended {
                    ctx.diags.push(Diagnostic::new(
                        format!("field `{}` follows a field that consumes the rest of the input", b.id),
                        b.span,
                    ));
                }
                if let Some(pad) = natural(&b.container, b.align, &mut alignment) {
                    emit_align(pad, &mut steps, &mut align, &mut exact, &mut min_bits);
                }
                let (cwidth, _) = match b.container.integer_info() {
                    Some(info) if !matches!(b.container, TypeNode::Bytes) => info,
                    _ => {
                        ctx.diags.push(Diagnostic::new(
                            format!("bitfield `{}` needs an integer container such as uint8 or u12", b.id),
                            b.span,
                        ));
                        (8, false)
                    }
                };
                let codec = ctx.codec_for(&b.container, b.endianness.clone(), &default_endian, align, b.span, &b.id);
                let total: u32 = b.members.iter().map(|m| m.width).sum();
                if total > cwidth {
                    ctx.diags.push(Diagnostic::new(
                        format!("bitfield `{}` members use {} bits but the container has only {}", b.id, total, cwidth),
                        b.span,
                    ));
                }
                let mut parts = Vec::new();
                let mut offset = 0u32;
                for m in &b.members {
                    if m.name != "_" && total <= cwidth {
                        let shift = match b.order {
                            BitOrder::Msb => cwidth - offset - m.width,
                            BitOrder::Lsb => offset,
                        };
                        if let Some(&idx) = ctx.names.get(&m.name) {
                            parts.push(BitPart { member: idx, shift, width: m.width, signed: m.signed });
                            available.insert(idx);
                        }
                    }
                    offset += m.width;
                }
                min_bits += cwidth as u64;
                align = align.advance(cwidth as u64);
                exact = exact.map(|x| x + cwidth as u64);
                steps.push(Step::Bitfield { container: codec, container_width: cwidth, parts });
            }
        }
        ctx.schedule_calcs(&mut steps, &available, &mut scheduled);
    }

    // C-style tail padding: the size is a multiple of the packet's alignment.
    if p.align.is_some() && !open_ended {
        emit_align(alignment, &mut steps, &mut align, &mut exact, &mut min_bits);
    }

    // Calculated fields that could never be evaluated.
    for item in &p.items {
        if let PacketItem::Calculated(c) = item {
            let idx = ctx.names[&c.name];
            if !scheduled.contains(&idx) && ctx.diags.is_empty() {
                ctx.diags.push(Diagnostic::new(format!("calculated field `{}` depends on itself", c.name), c.span));
            }
        }
    }

    if !align.is_aligned() {
        if align.modulus == 8 {
            ctx.diags.push(
                Diagnostic::new(
                    format!(
                        "packet `{}` ends {} bit(s) into a byte; packets must be a whole number of bytes",
                        p.name, align.offset
                    ),
                    p.span,
                )
                .with_note(format!("add `_ u{}` as padding at the end", 8 - align.offset)),
            );
        } else {
            ctx.diags.push(Diagnostic::new(
                format!("the size of packet `{}` may not be a whole number of bytes", p.name),
                p.span,
            ).with_note("a variable-length array of bit-sized elements must have a length whose bit count is a multiple of 8 (e.g. u12[n * 2])"));
        }
    }

    // Calculated members needed by encode (lengths depend on them).
    let mut needed = HashSet::<usize>::new();
    let mut stack = Vec::new();
    for m in &ctx.members {
        if let Some(Count::Expr(e)) = &m.array {
            e.deps(&mut stack);
        }
    }
    while let Some(m) = stack.pop() {
        if let MemberKind::Calculated(e) = &ctx.members[m].kind
            && needed.insert(m)
        {
            e.deps(&mut stack);
        }
    }
    let encode_calcs = steps
        .iter()
        .filter_map(|s| match s {
            Step::Calc { member } if needed.contains(member) => Some(*member),
            _ => None,
        })
        .collect();

    if !ctx.diags.is_empty() {
        return Err(ctx.diags);
    }
    let fixed_bits = if open_ended { None } else { exact };
    Ok(Packet {
        name: p.name.clone(),
        members: ctx.members,
        steps,
        encode_calcs,
        min_bits,
        open_ended,
        fixed_bits,
        alignment: if p.align.is_some() { alignment } else { 1 },
    })
}

impl<'a> Ctx<'a> {
    fn declare(&mut self, name: &str, ty: ValueType, kind: MemberKind, span: Span) {
        if name.starts_with("pb_") || name.starts_with("pbc_") || name.starts_with("_pb") {
            self.diags.push(Diagnostic::new(
                format!("field name `{}` is reserved (prefixes pb_, pbc_ and _pb are used by generated code)", name),
                span,
            ));
        }
        if self.names.contains_key(name) {
            self.diags.push(Diagnostic::new(
                format!("`{}` is declared more than once in packet `{}`", name, self.packet.name),
                span,
            ));
            return;
        }
        self.names.insert(name.to_string(), self.members.len());
        self.members.push(Member { name: name.to_string(), ty, array: None, kind });
    }

    fn codec_for(
        &mut self,
        t: &TypeNode,
        field_endian: Option<Endianness>,
        default_endian: &Endianness,
        align: Align,
        span: Span,
        name: &str,
    ) -> Codec {
        let explicit = field_endian.is_some();
        let endian = field_endian.unwrap_or_else(|| default_endian.clone());
        let aligned = align.is_aligned();
        let misaligned = |ctx: &mut Ctx, what: &str| {
            let at = align.describe();
            ctx.diags.push(
                Diagnostic::new(
                    format!("{} `{}` starts {}; {} must be byte aligned", type_label(t), name, at, what),
                    span,
                )
                .with_note(
                    "use a uN type for integers that live in the bit stream, or add `_ uN` padding before this field",
                ),
            );
        };
        match t {
            TypeNode::Packet(n) => {
                if !aligned {
                    misaligned(self, "nested packets");
                }
                Codec::Packet(n.clone())
            }
            TypeNode::Float32 | TypeNode::Float64 => {
                if !aligned {
                    misaligned(self, "floating point fields");
                }
                Codec::Float { width: t.bit_width().unwrap(), endian }
            }
            TypeNode::MacAddress => {
                if !aligned {
                    misaligned(self, "mac addresses");
                }
                Codec::Mac
            }
            TypeNode::Str | TypeNode::CStr | TypeNode::PrefixedStr { .. } => {
                // Strings go through string_codec; reaching here means a
                // string type was used where only integers are allowed.
                self.diags.push(Diagnostic::new(format!("`{}` cannot have a string type here", name), span));
                Codec::Bytes { nbytes: 1, endian }
            }
            TypeNode::Bits { width, .. } => {
                if aligned && width % 8 == 0 {
                    Codec::Bytes { nbytes: width / 8, endian }
                } else {
                    if explicit && *width > 8 {
                        self.diags.push(
                            Diagnostic::new(
                                format!(
                                    "`{}` is not a whole number of aligned bytes, so it cannot have a byte order",
                                    name
                                ),
                                span,
                            )
                            .with_note("bit-stream integers are always read most significant bit first"),
                        );
                    }
                    Codec::Bits { width: *width }
                }
            }
            other => {
                let width = other.bit_width().unwrap();
                if !aligned {
                    misaligned(self, "standard integer types");
                }
                Codec::Bytes { nbytes: width / 8, endian }
            }
        }
    }

    fn string_codec(
        &mut self,
        f: &crate::models::parsing_models::TypeExpr,
        default_endian: &Endianness,
        align: Align,
    ) -> Codec {
        if !align.is_aligned() {
            self.diags.push(
                Diagnostic::new(
                    format!("string `{}` starts {}; strings must be byte aligned", f.id, align.describe()),
                    f.span,
                )
                .with_note("add `_ uN` padding or `align 1` before this field"),
            );
        }
        if f.endianness.is_some() && !matches!(f.expr, TypeNode::PrefixedStr { .. }) {
            self.diags.push(Diagnostic::new(format!("string `{}` cannot have a byte order", f.id), f.span));
        }
        match &f.expr {
            TypeNode::Char => Codec::Str(StrMode::Padded),
            TypeNode::Str => Codec::Str(StrMode::Exact),
            TypeNode::CStr | TypeNode::PrefixedStr { .. } if f.array.is_some() => {
                self.diags.push(
                    Diagnostic::new(
                        format!("`{}` already determines its own length and cannot take [..]", f.id),
                        f.span,
                    )
                    .with_note("use char[n] or string[n] for strings whose length comes from elsewhere"),
                );
                Codec::Str(StrMode::CString)
            }
            TypeNode::CStr => Codec::Str(StrMode::CString),
            TypeNode::PrefixedStr { prefix, endianness } => {
                let width = match prefix.integer_info() {
                    Some((w, false)) if !matches!(**prefix, TypeNode::Bytes | TypeNode::Char) => w,
                    _ => {
                        self.diags.push(Diagnostic::new(
                            format!("the length prefix of `{}` must be an unsigned integer type", f.id),
                            f.span,
                        ));
                        8
                    }
                };
                let codec = self.codec_for(prefix, endianness.clone(), default_endian, align, f.span, &f.id);
                Codec::Str(StrMode::Prefixed { prefix: Box::new(codec), width })
            }
            _ => Codec::Str(StrMode::Exact),
        }
    }

    /// Add calculated fields to the decode steps once their inputs are known.
    fn schedule_calcs(&self, steps: &mut Vec<Step>, available: &HashSet<usize>, scheduled: &mut HashSet<usize>) {
        loop {
            let mut progressed = false;
            for (idx, m) in self.members.iter().enumerate() {
                if scheduled.contains(&idx) {
                    continue;
                }
                if let MemberKind::Calculated(e) = &m.kind {
                    let mut deps = Vec::new();
                    e.deps(&mut deps);
                    if deps.iter().all(|d| *d != idx && (available.contains(d) || scheduled.contains(d))) {
                        scheduled.insert(idx);
                        steps.push(Step::Calc { member: idx });
                        progressed = true;
                    }
                }
            }
            if !progressed {
                break;
            }
        }
    }

    fn require_available(
        &mut self,
        e: &TExpr,
        available: &HashSet<usize>,
        scheduled: &HashSet<usize>,
        span: Span,
        field: &str,
    ) {
        let mut deps = Vec::new();
        e.deps(&mut deps);
        for d in deps {
            if !available.contains(&d) && !scheduled.contains(&d) {
                let name = self.members[d].name.clone();
                self.diags.push(Diagnostic::new(
                    format!("the length of `{}` uses `{}`, which is not known yet at that point", field, name),
                    span,
                ).with_note("lengths may only use fields declared before them (or calculated fields that depend only on those)"));
            }
        }
    }

    fn check_expr(&mut self, e: &ExprNode, span: Span) -> Option<TExpr> {
        match self.typecheck(e) {
            Ok(t) => Some(t),
            Err(msg) => {
                self.diags.push(Diagnostic::new(msg, span));
                None
            }
        }
    }

    fn lookup(&self, name: &str) -> Result<usize, String> {
        self.names
            .get(name)
            .copied()
            .ok_or_else(|| format!("unknown field `{}` in packet `{}`", name, self.packet.name))
    }

    fn scalar_ty(&self, vt: &ValueType, name: &str) -> Result<Ty, String> {
        match vt {
            ValueType::Int { .. } => Ok(Ty::Int),
            ValueType::Float { .. } => Ok(Ty::Float),
            ValueType::Mac => Err(format!("`{}` is a mac address and cannot be used in an expression", name)),
            ValueType::Packet(_) => Err(format!("`{}` is a nested packet and cannot be used in an expression", name)),
            ValueType::Str => Err(format!("`{}` is a string and cannot be used in an expression", name)),
        }
    }

    fn typecheck(&self, e: &ExprNode) -> Result<TExpr, String> {
        use ExprNode::*;
        Ok(match e {
            NoExpr => return Err("empty expression".into()),
            UnsignedInteger64Value(v) => TExpr::IntLit(*v as i64),
            Integer64Value(v) => TExpr::IntLit(*v),
            Float64Value(v) => TExpr::FloatLit(*v),
            StringValue(_) => return Err("string literals are not supported in expressions".into()),
            ParenthesizedExpr(x) => self.typecheck(x)?,
            ValueReference(name, index) => {
                let idx = self.lookup(name)?;
                let m = &self.members[idx];
                let ty = self.scalar_ty(&m.ty, name)?;
                let is_array = self.is_array(idx);
                match index {
                    None => {
                        if is_array {
                            return Err(format!(
                                "`{}` is an array; index it (`{}[i]`) or use `sumof {}`",
                                name, name, name
                            ));
                        }
                        TExpr::Ref { member: idx, ty }
                    }
                    Some(ix) => {
                        if !is_array {
                            return Err(format!("`{}` is not an array and cannot be indexed", name));
                        }
                        let ix = coerce(self.typecheck(ix)?, Ty::Int);
                        TExpr::Index { member: idx, index: Box::new(ix), ty }
                    }
                }
            }
            AggregateSum(name) | AggregateProduct(name) => {
                let idx = self.lookup(name)?;
                if !self.is_array(idx) {
                    return Err(format!("`{}` is not an array", name));
                }
                let ty = self.scalar_ty(&self.members[idx].ty, name)?;
                let op = if matches!(e, AggregateSum(_)) { AggOp::Sum } else { AggOp::Product };
                TExpr::Aggregate { member: idx, op, ty }
            }
            ActivationRecord(fname, args) => {
                let args = args.iter().map(|a| self.typecheck(a)).collect::<Result<Vec<_>, _>>()?;
                match fname.as_str() {
                    "sqrt" => {
                        if args.len() != 1 {
                            return Err("sqrt takes exactly one argument".into());
                        }
                        let a = coerce(args.into_iter().next().unwrap(), Ty::Float);
                        TExpr::Call { func: Func::Sqrt, args: vec![a], ty: Ty::Float }
                    }
                    "min" | "max" => {
                        if args.len() != 2 {
                            return Err(format!("{} takes exactly two arguments", fname));
                        }
                        let mut it = args.into_iter();
                        let (a, b) = (it.next().unwrap(), it.next().unwrap());
                        let ty = numeric_join(a.ty(), b.ty());
                        let func = if fname == "min" { Func::Min } else { Func::Max };
                        TExpr::Call { func, args: vec![coerce(a, ty), coerce(b, ty)], ty }
                    }
                    other => return Err(format!("unknown function `{}`", other)),
                }
            }
            GuardExpression(c, t, o) => {
                let cond = coerce(self.typecheck(c)?, Ty::Bool);
                let (t, o) = (self.typecheck(t)?, self.typecheck(o)?);
                let ty = if t.ty() == Ty::Bool && o.ty() == Ty::Bool { Ty::Bool } else { numeric_join(t.ty(), o.ty()) };
                TExpr::Guard { cond: Box::new(cond), then: Box::new(coerce(t, ty)), other: Box::new(coerce(o, ty)), ty }
            }
            Plus(a, b) | Minus(a, b) | Mult(a, b) | Div(a, b) | Pow(a, b) => {
                let (a, b) = (self.typecheck(a)?, self.typecheck(b)?);
                let ty = numeric_join(a.ty(), b.ty());
                let op = match e {
                    Plus(..) => ArithOp::Add,
                    Minus(..) => ArithOp::Sub,
                    Mult(..) => ArithOp::Mul,
                    Div(..) => ArithOp::Div,
                    _ => ArithOp::Pow,
                };
                TExpr::Arith { op, a: Box::new(coerce(a, ty)), b: Box::new(coerce(b, ty)), ty }
            }
            Gt(a, b) | Gte(a, b) | Lt(a, b) | Lte(a, b) | Equals(a, b) | NotEquals(a, b) => {
                let (a, b) = (self.typecheck(a)?, self.typecheck(b)?);
                let ty = numeric_join(a.ty(), b.ty());
                let op = match e {
                    Gt(..) => CmpOp::Gt,
                    Gte(..) => CmpOp::Gte,
                    Lt(..) => CmpOp::Lt,
                    Lte(..) => CmpOp::Lte,
                    Equals(..) => CmpOp::Eq,
                    _ => CmpOp::Ne,
                };
                TExpr::Cmp { op, a: Box::new(coerce(a, ty)), b: Box::new(coerce(b, ty)) }
            }
            And(a, b) | Or(a, b) => {
                let a = coerce(self.typecheck(a)?, Ty::Bool);
                let b = coerce(self.typecheck(b)?, Ty::Bool);
                let op = if matches!(e, And(..)) { LogicOp::And } else { LogicOp::Or };
                TExpr::Logic { op, a: Box::new(a), b: Box::new(b) }
            }
        })
    }

    /// Arrays are known after pass 2; before that, look at the source.
    fn is_array(&self, idx: usize) -> bool {
        if self.members[idx].array.is_some() {
            return true;
        }
        let name = &self.members[idx].name;
        self.packet.items.iter().any(
            |it| matches!(it, PacketItem::Field(f) if &f.id == name && f.array.is_some() && field_value_type(f) != ValueType::Str),
        )
    }
}

/// Numeric type of a binary operation: float wins, booleans count as integers.
fn numeric_join(a: Ty, b: Ty) -> Ty {
    if a == Ty::Float || b == Ty::Float { Ty::Float } else { Ty::Int }
}

pub fn coerce(e: TExpr, to: Ty) -> TExpr {
    if e.ty() == to {
        return e;
    }
    TExpr::Convert { e: Box::new(e), to }
}

// ---------------------------------------------------------------------------
// Layout report
// ---------------------------------------------------------------------------

/// One row of a packet's layout, for display.
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutRow {
    /// Bit offset from the packet start, when it does not depend on the data.
    pub offset_bits: Option<u64>,
    /// Size in bits, when it does not depend on the data.
    pub size_bits: Option<u64>,
    /// Member name, `_` for padding, or the name of a bitfield member.
    pub name: String,
    pub kind: String,
    /// Indented under the previous row (bitfield members).
    pub nested: bool,
}

impl Module {
    /// Field-by-field layout of `packet`, including padding inserted by alignment.
    pub fn layout(&self, packet: &Packet) -> Vec<LayoutRow> {
        let mut rows = Vec::new();
        let mut offset = Some(0u64);
        for step in &packet.steps {
            match step {
                Step::Calc { .. } => {}
                Step::Align { bytes } => {
                    let unit = bytes * 8;
                    let size = offset.map(|o| (unit - o % unit) % unit);
                    if size != Some(0) {
                        rows.push(LayoutRow {
                            offset_bits: offset,
                            size_bits: size,
                            name: "_".into(),
                            kind: format!("padding to {} byte(s)", bytes),
                            nested: false,
                        });
                    }
                    offset = offset.zip(size).map(|(o, s)| o + s);
                }
                Step::Field { member, ty, codec, array } => {
                    let elem = match codec {
                        Codec::Packet(n) => self.packets.iter().find(|p| &p.name == n).and_then(|p| p.fixed_bits),
                        Codec::Str(StrMode::Padded | StrMode::Exact) => Some(8),
                        Codec::Str(_) => None,
                        c => Some(c.bits() as u64),
                    };
                    let (size, suffix) = match array {
                        None => (elem, String::new()),
                        Some(Count::Expr(e)) => match e.const_int() {
                            Some(n) if n >= 0 => (elem.map(|b| b * n as u64), format!("[{}]", n)),
                            _ => (None, "[n]".into()),
                        },
                        Some(Count::Remaining) => (None, "[]".into()),
                    };
                    let kind = match (ty, codec) {
                        (_, Codec::Str(StrMode::Padded)) => format!("char{}", suffix),
                        (_, Codec::Str(StrMode::Exact)) => format!("string{}", suffix),
                        (_, Codec::Str(StrMode::CString)) => "cstring".into(),
                        (_, Codec::Str(StrMode::Prefixed { width, .. })) => format!("string(u{} prefix)", width),
                        (ValueType::Int { width: 8, signed: false }, _) if array.is_some() => {
                            format!("bytes{}", suffix)
                        }
                        (ValueType::Int { width, signed }, _) => {
                            format!("{}{}{}", if *signed { "i" } else { "u" }, width, suffix)
                        }
                        (ValueType::Float { width }, _) => format!("float{}{}", width, suffix),
                        (ValueType::Mac, _) => format!("macaddress{}", suffix),
                        (ValueType::Packet(n), _) => format!("{}{}", n, suffix),
                        (ValueType::Str, _) => "string".into(),
                    };
                    let name = member.map(|m| packet.members[m].name.clone()).unwrap_or_else(|| "_".into());
                    rows.push(LayoutRow { offset_bits: offset, size_bits: size, name, kind, nested: false });
                    offset = offset.zip(size).map(|(o, s)| o + s);
                }
                Step::Bitfield { container_width, parts, .. } => {
                    rows.push(LayoutRow {
                        offset_bits: offset,
                        size_bits: Some(*container_width as u64),
                        name: "(bitfield)".into(),
                        kind: format!("u{} container", container_width),
                        nested: false,
                    });
                    for part in parts {
                        let m = &packet.members[part.member];
                        rows.push(LayoutRow {
                            offset_bits: offset.map(|o| o + (*container_width - part.shift - part.width) as u64),
                            size_bits: Some(part.width as u64),
                            name: m.name.clone(),
                            kind: format!(
                                "{}{} (bits {}..{})",
                                if part.signed { "i" } else { "u" },
                                part.width,
                                part.shift + part.width - 1,
                                part.shift
                            ),
                            nested: true,
                        });
                    }
                    offset = offset.map(|o| o + *container_width as u64);
                }
            }
        }
        rows
    }
}
