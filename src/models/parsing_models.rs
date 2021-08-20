#[derive(Debug, Clone)]
pub enum ExprNode {
    UnsignedInteger8(Option<usize>),
    UnsignedInteger16(Option<usize>),
    UnsignedInteger32(Option<usize>),
    UnsignedInteger64(Option<usize>),
    UnsignedInteger64Value(u64),
    Integer8(Option<usize>),
    Integer16(Option<usize>),
    Integer32(Option<usize>),
    Integer64(Option<usize>),
    Integer64Value(i64),
    Float32(Option<usize>),
    Float64(Option<usize>),
    Float64Value(f64),
    ValueReference(String, Option<usize>),
    MacAddress,
    ParenthesizedExpr(Box<ExprNode>),
    Plus(Box<ExprNode>, Box<ExprNode>),
    Minus(Box<ExprNode>, Box<ExprNode>),
    Mult(Box<ExprNode>, Box<ExprNode>),
    Div(Box<ExprNode>, Box<ExprNode>),
    Pow(Box<ExprNode>, Box<ExprNode>),
    Gt(Box<ExprNode>, Box<ExprNode>),
    Lt(Box<ExprNode>, Box<ExprNode>),
    Gte(Box<ExprNode>, Box<ExprNode>),
    Lte(Box<ExprNode>, Box<ExprNode>),
    Equals(Box<ExprNode>, Box<ExprNode>),
    NotEquals(Box<ExprNode>, Box<ExprNode>),
    And(Box<ExprNode>, Box<ExprNode>),
    Or(Box<ExprNode>, Box<ExprNode>),
    GuardExpression(Box<ExprNode>, Box<ExprNode>),
    SumOf(Box<ExprNode>),
    ProductOf(Box<ExprNode>),
    ActivationRecord(String, Vec<ExprNode>),
    NoExpr,
}

impl ExprNode {
    pub fn get_type_length_bytes(&self) -> usize {
        match self {
            ExprNode::UnsignedInteger8(_) => 1,
            ExprNode::Integer8(_) => 1,
            ExprNode::UnsignedInteger16(_) => 2,
            ExprNode::Integer16(_) => 2,
            ExprNode::UnsignedInteger32(_) => 4,
            ExprNode::Integer32(_) => 4,
            ExprNode::UnsignedInteger64(_) => 8,
            ExprNode::Integer64(_) => 8,
            ExprNode::Float32(_) => 4,
            ExprNode::Float64(_) => 8,
            ExprNode::MacAddress => 6,
            _ => 0,
        }
    }
    pub fn get_length_bytes(&self) -> usize {
        match self {
            ExprNode::UnsignedInteger8(y) => match y {
                Some(n) => *n,
                None => 1,
            },
            ExprNode::Integer8(y) => match y {
                Some(n) => *n,
                None => 1,
            },
            ExprNode::UnsignedInteger16(y) => match y {
                Some(n) => n * 2,
                None => 2,
            },
            ExprNode::Integer16(y) => match y {
                Some(n) => n * 2,
                None => 2,
            },
            ExprNode::UnsignedInteger32(y) => match y {
                Some(n) => n * 4,
                None => 4,
            },
            ExprNode::Integer32(y) => match y {
                Some(n) => n * 4,
                None => 4,
            },
            ExprNode::UnsignedInteger64(y) => match y {
                Some(n) => n * 8,
                None => 8,
            },
            ExprNode::Integer64(y) => match y {
                Some(n) => n * 8,
                None => 8,
            },
            ExprNode::Float32(y) => match y {
                Some(n) => n * 4,
                None => 4,
            },
            ExprNode::Float64(y) => match y {
                Some(n) => n * 8,
                None => 8,
            },
            ExprNode::MacAddress => 6,
            _ => 0,
        }
    }
}

#[derive(Debug)]
pub struct TypeExpr {
    pub id: String,
    pub expr: ExprNode,
}

#[derive(Debug)]
pub struct PacketExpr {
    pub name: String,
    pub fields: Vec<TypeExpr>,
    pub calculated_fields: Vec<CalculatedField>,
}

impl PacketExpr {
    pub fn get_total_length(&self) -> usize {
        let mut result = 0;
        for field in &self.fields {
            result += field.expr.get_length_bytes();
        }
        result
    }
}

#[derive(Debug)]
pub struct CalculatedField {
    pub name: String,
    pub type_name: String,
    pub expr: Box<ExprNode>,
    pub guard_expr: Option<Box<ExprNode>>
}
