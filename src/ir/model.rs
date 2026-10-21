//! The validated, language-independent packet model every backend consumes.

use std::collections::HashSet;

use super::expr::{Mark, TExpr};
pub use super::wire::{BitPart, Codec, Count, Step, StrMode};
pub use crate::ast::{Radix, TextEncoding, VarintKind};

#[derive(Debug, Clone)]
pub struct Module {
    pub packets: Vec<Packet>,
    /// Standalone named constants, in source order.
    pub constants: Vec<Constant>,
    /// Categories of named constants, in source order.
    pub categories: Vec<Category>,
    /// Tagged unions (`body switch kind { ... }`), in packet order.
    pub unions: Vec<Union>,
    /// Wireshark dissectors to generate (`dissector` declarations).
    pub dissectors: Vec<Dissector>,
    /// `version N`: the versions generated code accepts, `min..=latest`
    /// (1..=N unless generated for a subset); None without versions.
    pub versions: Option<Versions>,
}

/// The protocol versions a module speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Versions {
    pub min: u32,
    /// The default when nothing else says which version to use.
    pub latest: u32,
}

/// A Wireshark dissector for a packet.
#[derive(Debug, Clone, PartialEq)]
pub struct Dissector {
    pub packet: String,
    /// The protocol's long name (`AIM OSCAR`).
    pub name: String,
    /// The filter name and field prefix (`oscar`).
    pub abbrev: String,
    /// Dissector tables to register in: (`tcp.port`, 5190).
    pub tables: Vec<(String, u64)>,
    /// Also try the dissector on TCP/UDP payloads (`heuristic`).
    pub heuristic: bool,
}

impl Dissector {
    /// Defaults: the packet's name, and its lowercase as the abbreviation.
    pub fn new(packet: &str) -> Self {
        Dissector {
            packet: packet.to_string(),
            name: packet.to_string(),
            abbrev: packet.to_ascii_lowercase(),
            tables: Vec::new(),
            heuristic: false,
        }
    }

    /// Wireshark protocol filter names: a lowercase letter, then lowercase
    /// letters, digits, `_`, `-` and `.`.
    pub fn check_abbrev(abbrev: &str) -> Result<(), String> {
        let ok = abbrev.starts_with(|c: char| c.is_ascii_lowercase())
            && abbrev.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_-.".contains(c));
        if ok {
            Ok(())
        } else {
            Err(format!("`{}` is not a protocol abbreviation (lowercase letters, digits, _ - and .)", abbrev))
        }
    }
}

/// A tagged union: the type of a `switch` member.
#[derive(Debug, Clone)]
pub struct Union {
    /// `<Packet><Field>` in PascalCase, e.g. `FlapBody`.
    pub name: String,
    pub arms: Vec<Arm>,
}

impl Union {
    pub fn default_arm(&self) -> Option<&Arm> {
        self.arms.iter().find(|a| a.default)
    }
}

/// One arm of a union.
#[derive(Debug, Clone)]
pub struct Arm {
    pub name: String,
    /// The selector values that pick this arm (none for the default arm).
    pub values: Vec<i64>,
    /// `_`: any value no other arm lists.
    pub default: bool,
    /// What the arm holds: an integer, a packet or bytes (`Int` 8-bit with a
    /// count); None for an empty arm.
    pub ty: Option<ValueType>,
    pub codec: Option<Codec>,
    /// For bytes arms: the byte count.
    pub count: Option<Count>,
}

impl Arm {
    /// A byte buffer (`raw bytes[n]`).
    pub fn is_bytes(&self) -> bool {
        self.count.is_some()
    }
}

/// A named value from a `const` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Constant {
    pub name: String,
    /// Always an integer type.
    pub ty: ValueType,
    /// The value as 64-bit two's complement (a uint64 above i64::MAX is negative here).
    pub value: i64,
    /// How the value was written, so generated code can keep the spelling.
    pub radix: Radix,
    pub note: Option<String>,
    /// For versioned constants: the value of each range of versions, in
    /// increasing order (`value` is the latest one's). Empty otherwise.
    pub versions: Vec<ConstVersion>,
}

/// The value a constant has for versions `from..=to`.
#[derive(Debug, Clone, PartialEq)]
pub struct ConstVersion {
    pub from: u32,
    pub to: u32,
    pub value: i64,
    pub radix: Radix,
}

impl Constant {
    /// The value as written for an unsigned or signed type, in its radix
    /// (hex for `0x`/`0b` sources, unless the value is negative).
    pub fn literal(&self) -> String {
        if self.ty.is_signed() {
            if self.value < 0 || self.radix == Radix::Dec {
                return self.value.to_string();
            }
            return format!("0x{:x}", self.value);
        }
        let v = self.value as u64;
        match self.radix {
            Radix::Dec => v.to_string(),
            Radix::Hex | Radix::Bin => format!("0x{:x}", v),
        }
    }
}

/// `const Name type { a = 1, ... }`: a group of related named constants.
#[derive(Debug, Clone, PartialEq)]
pub struct Category {
    pub name: String,
    pub ty: ValueType,
    pub members: Vec<Constant>,
}

impl ValueType {
    /// True if the 64-bit two's complement `value` is representable in this
    /// integer type (any bit pattern fits a 64-bit unsigned).
    pub fn holds(&self, value: i64) -> bool {
        match *self {
            ValueType::Int { width: 64, .. } => true,
            ValueType::Int { width, signed: true } => {
                let half = 1i64 << (width - 1);
                (-half..half).contains(&value)
            }
            ValueType::Int { width, signed: false } => (0..1i64 << width).contains(&value),
            _ => false,
        }
    }
}

impl Module {
    pub fn union(&self, name: &str) -> Option<&Union> {
        self.unions.iter().find(|u| u.name == name)
    }

    /// Packets ordered so that every packet comes after the packets it
    /// contains by value (needed by languages that require declaration before
    /// use). Arrays are stored out of line, so they do not count: that is how
    /// a packet can contain itself.
    pub fn in_dependency_order(&self) -> Vec<&Packet> {
        fn visit<'a>(m: &'a Module, p: &'a Packet, seen: &mut HashSet<String>, out: &mut Vec<&'a Packet>) {
            if !seen.insert(p.name.clone()) {
                return;
            }
            for member in p.members.iter().filter(|m| m.array.is_none()) {
                let mut deps: Vec<&String> = Vec::new();
                match &member.ty {
                    ValueType::Packet(n) => deps.push(n),
                    ValueType::Union(u) => {
                        for arm in m.union(u).map(|u| u.arms.as_slice()).unwrap_or(&[]) {
                            if let Some(ValueType::Packet(n)) = &arm.ty {
                                deps.push(n);
                            }
                        }
                    }
                    _ => {}
                }
                for n in deps {
                    if let Some(dep) = m.packets.iter().find(|x| &x.name == n) {
                        visit(m, dep, seen, out);
                    }
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
    /// Values passed in by the containing packet (`packet Body(version uint8)`).
    pub params: Vec<Param>,
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
    /// `assert` items, in source order (`Step::Assert` refers to them).
    pub asserts: Vec<Assertion>,
    /// Derived members, which decoding verifies after the last step.
    pub derived: Vec<usize>,
    /// Derived members whose value depends on the encoded bytes (`sizeof`,
    /// `offsetof`, checksums): encoding writes a placeholder and patches it
    /// after the last step, in this order.
    pub patches: Vec<usize>,
    /// Members only known after encoding the body: `patches` and the
    /// calculated members that depend on them.
    pub wire_dependent: Vec<usize>,
    /// A member derived from `version` (`ver uint8 = version`): decoding
    /// adopts its value as the reader's version, encoding takes the
    /// writer's (or, if the caller gave none, the member's).
    pub version_member: Option<usize>,
    /// The module's versions (`Module::versions`), for generated code.
    pub versions: Option<Versions>,
}

/// A packet parameter: an integer the containing packet passes in. It is
/// not stored; expressions read it as `TExpr::Param`.
#[derive(Debug, Clone, PartialEq)]
pub struct Param {
    pub name: String,
    pub ty: ValueType,
}

/// A nested packet and the arguments for its parameters: i64 expressions
/// over the containing packet, converted to the parameter types (`types`).
#[derive(Debug, Clone, PartialEq)]
pub struct PacketRef {
    pub name: String,
    pub args: Vec<TExpr>,
    pub types: Vec<ValueType>,
}

impl PacketRef {
    pub fn new(name: &str) -> Self {
        PacketRef { name: name.to_string(), args: Vec::new(), types: Vec::new() }
    }

    /// Each argument with the type of its parameter.
    pub fn typed_args(&self) -> impl Iterator<Item = (&TExpr, &ValueType)> {
        self.args.iter().zip(&self.types)
    }
}

/// `assert cond "message"`.
#[derive(Debug, Clone)]
pub struct Assertion {
    pub cond: TExpr,
    pub message: String,
}

impl Packet {
    /// True if decoding/encoding needs the packet's start position.
    pub fn uses_align(&self) -> bool {
        self.steps.iter().any(|s| matches!(s, Step::Align { .. }))
    }

    /// Members that encoding evaluates up front (calculated members lengths
    /// need, and derived members that only depend on values), with their
    /// expressions, dependencies first.
    pub fn encode_calc_members(&self) -> impl Iterator<Item = (&Member, &TExpr)> {
        self.encode_calcs.iter().filter_map(|&c| {
            let m = &self.members[c];
            m.calc_expr().or(m.derived_expr()).map(|e| (m, e))
        })
    }

    /// True if `e` reads a member only known after encoding the body; such
    /// length checks and assertions are skipped when encoding.
    pub fn depends_on_wire(&self, e: &TExpr) -> bool {
        let mut deps = Vec::new();
        e.deps(&mut deps);
        deps.iter().any(|d| self.wire_dependent.contains(d))
    }

    /// The versions generated code accepts: (min, latest); (1, 1) without versions.
    pub fn version_bounds(&self) -> (u32, u32) {
        self.versions.map(|v| (v.min, v.latest)).unwrap_or((1, 1))
    }

    /// The indices of the steps inside a version gate.
    pub fn gated_steps(&self) -> HashSet<usize> {
        let mut out = HashSet::new();
        let mut depth = 0usize;
        for (i, s) in self.steps.iter().enumerate() {
            match s {
                Step::OpenGate { .. } => depth += 1,
                Step::CloseGate { .. } => depth = depth.saturating_sub(1),
                _ if depth > 0 => {
                    out.insert(i);
                }
                _ => {}
            }
        }
        out
    }

    /// The step that reads or writes stored member `member` (the first, for
    /// a member declared again for other versions).
    pub fn field_step(&self, member: usize) -> Option<usize> {
        self.field_steps(member).first().copied()
    }

    /// Every step that reads or writes stored member `member`: one per
    /// declaration (several for one declared again for other versions).
    pub fn field_steps(&self, member: usize) -> Vec<usize> {
        let at = |s: &Step| matches!(s, Step::Field { member: Some(m), .. } if *m == member);
        self.steps.iter().enumerate().filter(|(_, s)| at(s)).map(|(i, _)| i).collect()
    }

    /// The test of the gate step `step` is in, if any.
    pub fn gate_of(&self, step: usize) -> Option<&TExpr> {
        let mut open = None;
        for (i, s) in self.steps.iter().enumerate().take(step + 1) {
            match s {
                Step::OpenGate { cond, .. } => open = Some(cond),
                Step::CloseGate { .. } if i < step => open = None,
                _ => {}
            }
        }
        open
    }

    /// The `CloseGate` step of the gate opened at step `open`.
    pub fn gate_end(&self, open: usize) -> usize {
        (open..self.steps.len())
            .find(|&i| matches!(self.steps[i], Step::CloseGate { open: o } if o == open))
            .unwrap_or(self.steps.len())
    }

    /// The positions decoding (`encoding == false`) or encoding records: the
    /// marks read by verified or patched derived fields, and the position of
    /// each patched field.
    pub fn marks(&self, encoding: bool) -> Vec<Mark> {
        let mut out = Vec::new();
        let members: &[usize] = if encoding { &self.patches } else { &self.derived };
        for &m in members {
            let member = &self.members[m];
            if !encoding && member.lenient {
                continue;
            }
            if let Some(e) = member.derived_expr() {
                e.marks(&mut out);
            }
            if encoding {
                // Every declaration's position (one per version range).
                out.extend(self.field_steps(m).into_iter().map(Mark::Before));
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// True if decoding or encoding needs the packet's start position
    /// (`pb_start`): for alignment, or for a mark.
    pub fn needs_start(&self, encoding: bool) -> bool {
        self.uses_align()
            || self.marks(encoding).contains(&Mark::PacketStart)
            || self.steps.iter().any(|s| matches!(s, Step::At { root: false, .. }))
    }
}

#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub ty: ValueType,
    pub array: Option<Count>,
    pub kind: MemberKind,
    /// `: Category`: the named constants this member's values come from.
    pub category: Option<String>,
    /// Declared checks on the value (`== v`, `in a..b`, `: Category strict`).
    pub checks: Vec<Check>,
    /// `lenient`: generated codecs do not enforce `checks`.
    pub lenient: bool,
    /// For strings: how characters become bytes.
    pub encoding: TextEncoding,
    /// The test for the versions the member is on the wire in, when that is
    /// not every version (it keeps its default value in the others).
    pub present: Option<TExpr>,
}

/// A declared check on a member's value. Decoding fails with a `constraint`
/// error when `cond` is false (after reading the member); encoding fails
/// before writing it.
#[derive(Debug, Clone)]
pub struct Check {
    pub kind: CheckKind,
    pub cond: TExpr,
    /// What the value must be, for error messages ("`start` must be 0x2a").
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CheckKind {
    /// `== value`: a magic value; the member also defaults to it.
    Equals(i64),
    /// `in lo..hi`, inclusive.
    Range(i64, i64),
    /// `: Category strict`: one of the category's values.
    InCategory(String),
}

impl Member {
    /// The value of a `== value` check: what the member defaults to.
    pub fn magic(&self) -> Option<i64> {
        self.checks.iter().find_map(|c| match c.kind {
            CheckKind::Equals(v) => Some(v),
            _ => None,
        })
    }

    /// The checks generated codecs enforce (none for `lenient` members).
    pub fn enforced_checks(&self) -> &[Check] {
        if self.lenient { &[] } else { &self.checks }
    }

    pub fn is_calculated(&self) -> bool {
        matches!(self.kind, MemberKind::Calculated(_))
    }

    /// A calculated member that reads `remaining`: decoders compute it from
    /// the input, encoders use its stored value instead of recomputing it.
    pub fn is_decode_only(&self) -> bool {
        self.calc_expr().is_some_and(TExpr::uses_remaining)
    }

    /// The expression of a calculated member.
    pub fn calc_expr(&self) -> Option<&TExpr> {
        match &self.kind {
            MemberKind::Calculated(e) => Some(e),
            _ => None,
        }
    }

    /// The expression of a derived member (`length uint16 = len(payload)`).
    pub fn derived_expr(&self) -> Option<&TExpr> {
        match &self.kind {
            MemberKind::Derived(e) => Some(e),
            _ => None,
        }
    }

    /// The `placeholder` of a derived member: the derived expression is then
    /// `when <stored value> == placeholder then placeholder otherwise ...`.
    pub fn placeholder(&self) -> Option<i64> {
        let TExpr::Guard { cond, then, .. } = self.derived_expr()? else { return None };
        match (cond.as_ref(), then.as_ref()) {
            (TExpr::Cmp { a, b, .. }, TExpr::IntLit(v))
                if matches!(a.as_ref(), TExpr::Stored { .. }) && matches!(b.as_ref(), TExpr::IntLit(w) if w == v) =>
            {
                Some(*v)
            }
            _ => None,
        }
    }

    pub fn is_derived(&self) -> bool {
        matches!(self.kind, MemberKind::Derived(_))
    }
}

#[derive(Debug, Clone)]
pub enum MemberKind {
    Stored,
    BitfieldPart,
    Calculated(TExpr),
    /// Stored on the wire, but computed when encoding and verified when
    /// decoding.
    Derived(TExpr),
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
    /// A tagged union (`Module::unions`).
    Union(String),
}

impl ValueType {
    /// Width of the native integer used to hold the value (8/16/32/64).
    pub fn storage_bits(&self) -> u32 {
        match self {
            ValueType::Int { width, .. } => storage_for(*width),
            ValueType::Float { width } => *width,
            ValueType::Mac => 48,
            ValueType::Packet(_) | ValueType::Str | ValueType::Union(_) => 0,
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
