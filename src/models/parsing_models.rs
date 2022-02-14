#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "size")]
pub enum TypeNode {
    UnsignedInteger8(Option<usize>),
    UnsignedInteger16(Option<usize>),
    UnsignedInteger32(Option<usize>),
    UnsignedInteger64(Option<usize>),
    Integer8(Option<usize>),
    Integer16(Option<usize>),
    Integer32(Option<usize>),
    Integer64(Option<usize>),
    Float32(Option<usize>),
    Float64(Option<usize>),
    MacAddress
}

impl TypeNode {
    pub fn get_type_length_bytes(&self) -> usize {
        match self {
            TypeNode::UnsignedInteger8(_) => 1,
            TypeNode::Integer8(_) => 1,
            TypeNode::UnsignedInteger16(_) => 2,
            TypeNode::Integer16(_) => 2,
            TypeNode::UnsignedInteger32(_) => 4,
            TypeNode::Integer32(_) => 4,
            TypeNode::UnsignedInteger64(_) => 8,
            TypeNode::Integer64(_) => 8,
            TypeNode::Float32(_) => 4,
            TypeNode::Float64(_) => 8,
            TypeNode::MacAddress => 6,
            _ => 0,
        }
    }
    pub fn get_length_bytes(&self) -> usize {
        match self {
            TypeNode::UnsignedInteger8(y) => match y {
                Some(n) => *n,
                None => 1,
            },
            TypeNode::Integer8(y) => match y {
                Some(n) => *n,
                None => 1,
            },
            TypeNode::UnsignedInteger16(y) => match y {
                Some(n) => n * 2,
                None => 2,
            },
            TypeNode::Integer16(y) => match y {
                Some(n) => n * 2,
                None => 2,
            },
            TypeNode::UnsignedInteger32(y) => match y {
                Some(n) => n * 4,
                None => 4,
            },
            TypeNode::Integer32(y) => match y {
                Some(n) => n * 4,
                None => 4,
            },
            TypeNode::UnsignedInteger64(y) => match y {
                Some(n) => n * 8,
                None => 8,
            },
            TypeNode::Integer64(y) => match y {
                Some(n) => n * 8,
                None => 8,
            },
            TypeNode::Float32(y) => match y {
                Some(n) => n * 4,
                None => 4,
            },
            TypeNode::Float64(y) => match y {
                Some(n) => n * 8,
                None => 8,
            },
            TypeNode::MacAddress => 6,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "content")]
pub enum ExprNode {
    UnsignedInteger64Value(u64),
    Integer64Value(i64),
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
    GuardExpression(Box<ExprNode>, Box<ExprNode>, Box<ExprNode>),
    SumOf(Box<ExprNode>),
    ProductOf(Box<ExprNode>),
    ActivationRecord(String, Vec<ExprNode>),
    NoExpr,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TypeExpr {
    pub id: String,
    pub expr: TypeNode,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct CalculatedField {
    pub name: String,
    pub data_type: String,
    pub expr: Box<ExprNode>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PacketExprList {
    pub packets: Vec<PacketExpr>
}
