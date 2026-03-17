#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endianness {
    Le,
    Be,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExprNode {
    NoExpr,
    UnsignedInteger64Value(u64),
    Integer64Value(i64),
    Float64Value(f64),
    StringValue(String),

    // identifiers and optional index expression (e.g., foo[expr])
    ValueReference(String, Option<Box<ExprNode>>),

    // function call: name(args...)
    ActivationRecord(String, Vec<Box<ExprNode>>),

    ParenthesizedExpr(Box<ExprNode>),
    GuardExpression(Box<ExprNode>, Box<ExprNode>, Box<ExprNode>), // when cond then a otherwise b

    // aggregates: sumof foo / productof bar
    AggregateSum(String),
    AggregateProduct(String),

    // arithmetic
    Plus(Box<ExprNode>, Box<ExprNode>),
    Minus(Box<ExprNode>, Box<ExprNode>),
    Mult(Box<ExprNode>, Box<ExprNode>),
    Div(Box<ExprNode>, Box<ExprNode>),
    Pow(Box<ExprNode>, Box<ExprNode>),

    // comparisons
    Gt(Box<ExprNode>, Box<ExprNode>),
    Gte(Box<ExprNode>, Box<ExprNode>),
    Lt(Box<ExprNode>, Box<ExprNode>),
    Lte(Box<ExprNode>, Box<ExprNode>),
    Equals(Box<ExprNode>, Box<ExprNode>),
    NotEquals(Box<ExprNode>, Box<ExprNode>),

    // boolean
    And(Box<ExprNode>, Box<ExprNode>),
    Or(Box<ExprNode>, Box<ExprNode>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypeNode {
    Integer8(Option<ExprNode>),
    UnsignedInteger8(Option<ExprNode>),
    Integer16(Option<ExprNode>),
    UnsignedInteger16(Option<ExprNode>),
    Integer32(Option<ExprNode>),
    UnsignedInteger32(Option<ExprNode>),
    Integer64(Option<ExprNode>),
    UnsignedInteger64(Option<ExprNode>),
    Float32(Option<ExprNode>),
    Float64(Option<ExprNode>),
    MacAddress(Option<ExprNode>),
    DateTime(Option<ExprNode>),
    Bytes(Option<ExprNode>), // opaque blob
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypeExpr {
    pub id: String,
    pub expr: TypeNode,
    pub endianness: Option<Endianness>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CalculatedField {
    pub name: String,
    pub data_type: String, // textual typename as written (e.g. "uint16")
    pub expr: Box<ExprNode>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketExpr {
    pub name: String,
    pub fields: Vec<TypeExpr>,
    pub calculated_fields: Vec<CalculatedField>,
    pub endianness: Option<Endianness>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketExprList {
    pub packets: Vec<PacketExpr>,
}

impl TypeNode {
    pub fn scalar_width_bytes(&self) -> usize {
        match self {
            TypeNode::UnsignedInteger8(_)  => 1,
            TypeNode::Integer8(_)          => 1,
            TypeNode::UnsignedInteger16(_) => 2,
            TypeNode::Integer16(_)         => 2,
            TypeNode::UnsignedInteger32(_) => 4,
            TypeNode::Integer32(_)         => 4,
            TypeNode::UnsignedInteger64(_) => 8,
            TypeNode::Integer64(_)         => 8,
            TypeNode::Float32(_)           => 4,
            TypeNode::Float64(_)           => 8,
            TypeNode::MacAddress(_)        => 6,
            TypeNode::DateTime(_)          => 8,
            TypeNode::Bytes(_)             => 1,
        }
    }

    pub fn get_type_length_bytes(&self) -> usize {
        self.scalar_width_bytes()
    }

    pub fn get_length_bytes(&self) -> usize {
        match self {
            TypeNode::Bytes(len_expr_opt) => {
                len_expr_opt
                    .as_ref()
                    .and_then(eval_len_count)
                    .unwrap_or(0)
            }

            TypeNode::UnsignedInteger8(m)
            | TypeNode::Integer8(m)
            | TypeNode::UnsignedInteger16(m)
            | TypeNode::Integer16(m)
            | TypeNode::UnsignedInteger32(m)
            | TypeNode::Integer32(m)
            | TypeNode::UnsignedInteger64(m)
            | TypeNode::Integer64(m)
            | TypeNode::Float32(m)
            | TypeNode::Float64(m)
            | TypeNode::MacAddress(m)
            | TypeNode::DateTime(m) => {
                let elem = self.scalar_width_bytes();
                let count = m.as_ref().and_then(eval_len_count).unwrap_or(1);
                elem * count
            }
        }
    }
}


fn eval_len_count(expr: &ExprNode) -> Option<usize> {
    eval_i128(expr).and_then(|n| if n >= 0 { Some(n as usize) } else { None })
}

fn eval_i128(e: &ExprNode) -> Option<i128> {
    use ExprNode::*;

    match e {
        UnsignedInteger64Value(u) => Some(*u as i128),
        Integer64Value(i)         => Some(*i as i128),
        Float64Value(f)           => Some(*f as i128), // truncation
        StringValue(_)            => None,

        ParenthesizedExpr(inner)  => eval_i128(inner),

        Plus(a, b)  => Some(eval_i128(a)? + eval_i128(b)?),
        Minus(a, b) => Some(eval_i128(a)? - eval_i128(b)?),
        Mult(a, b)  => Some(eval_i128(a)? * eval_i128(b)?),
        Div(a, b)   => {
            let rhs = eval_i128(b)?;
            if rhs == 0 { None } else { Some(eval_i128(a)? / rhs) }
        }
        Pow(a, b)   => {
            let base = eval_i128(a)?;
            let exp  = eval_i128(b)?;
            if exp < 0 { return None; }
            Some(ipow_i128(base, exp as u32)?)
        }

        GuardExpression(cond, then_e, else_e) => {
            let c = eval_bool(cond)?;
            if c { eval_i128(then_e) } else { eval_i128(else_e) }
        }

        // booleans as integers (rarely needed directly, but helpful for guards)
        Gt(a, b)      => Some((eval_i128(a)? >  eval_i128(b)?) as i128),
        Gte(a, b)     => Some((eval_i128(a)? >= eval_i128(b)?) as i128),
        Lt(a, b)      => Some((eval_i128(a)? <  eval_i128(b)?) as i128),
        Lte(a, b)     => Some((eval_i128(a)? <= eval_i128(b)?) as i128),
        Equals(a, b)  => Some((eval_i128(a)? == eval_i128(b)?) as i128),
        NotEquals(a,b)=> Some((eval_i128(a)? != eval_i128(b)?) as i128),

        And(a, b)     => Some((eval_bool(a)? && eval_bool(b)?) as i128),
        Or(a, b)      => Some((eval_bool(a)? || eval_bool(b)?) as i128),

        // Non-constant constructs we cannot resolve here (need runtime context):
        ValueReference(_, _) |
        ActivationRecord(_, _) |
        AggregateSum(_) |
        AggregateProduct(_) => None,

        NoExpr => None,
    }
}

fn eval_bool(e: &ExprNode) -> Option<bool> {
    use ExprNode::*;
    match e {
        Gt(a, b)      => Some(eval_i128(a)? >  eval_i128(b)?),
        Gte(a, b)     => Some(eval_i128(a)? >= eval_i128(b)?),
        Lt(a, b)      => Some(eval_i128(a)? <  eval_i128(b)?),
        Lte(a, b)     => Some(eval_i128(a)? <= eval_i128(b)?),
        Equals(a, b)  => Some(eval_i128(a)? == eval_i128(b)?),
        NotEquals(a,b)=> Some(eval_i128(a)? != eval_i128(b)?),
        And(a, b)     => Some(eval_bool(a)? && eval_bool(b)?),
        Or(a, b)      => Some(eval_bool(a)? || eval_bool(b)?),
        ParenthesizedExpr(inner) => eval_bool(inner),
        // allow numeric-as-bool (nonzero -> true) if it's a pure constant
        UnsignedInteger64Value(_) |
        Integer64Value(_) |
        Float64Value(_) => Some(eval_i128(e)? != 0),
        _ => None,
    }
}

fn ipow_i128(mut base: i128, mut exp: u32) -> Option<i128> {
    let mut acc: i128 = 1;
    while exp > 0 {
        if (exp & 1) == 1 {
            acc = acc.checked_mul(base)?;
        }
        exp >>= 1;
        if exp > 0 {
            base = base.checked_mul(base)?;
        }
    }
    Some(acc)
}