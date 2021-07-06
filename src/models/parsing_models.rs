#[derive(Debug)]
pub enum ExprNode {
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
    Identifier(String),
    MacAddress,
    Plus(Box<ExprNode>, Box<ExprNode>),
    Minus(Box<ExprNode>, Box<ExprNode>),
    Mult(Box<ExprNode>, Box<ExprNode>),
    Div(Box<ExprNode>, Box<ExprNode>),
    Pow(Box<ExprNode>, Box<ExprNode>),
    SumOf(String),
    ProductOf(String),
}

impl ExprNode {
    pub fn get_length(&self) -> usize {
        match self {
            ExprNode::UnsignedInteger8(y) => {
                match y {
                    Some(n) => 0,
                    None => 0
                }
            }
            ExprNode::Integer8(y) => {
                match y {
                    Some(n) => 0,
                    None => 0
                }
            }
            ExprNode::UnsignedInteger16(y) => {
                match y {
                    Some(n) => 0,
                    None => 0
                }
            }
            ExprNode::Integer16(y) => {
                match y {
                    Some(n) => 0,
                    None => 0
                }
            }
            ExprNode::UnsignedInteger32(y) => {
                match y {
                    Some(n) => 0,
                    None => 0
                }
            }
            ExprNode::Integer32(y) => {
                match y {
                    Some(n) => 0,
                    None => 0
                }
            }
            ExprNode::UnsignedInteger64(y) => {
                match y {
                    Some(n) => 0,
                    None => 0
                }
            }
            ExprNode::Integer64(y) => {
                match y {
                    Some(n) => 0,
                    None => 0
                }
            }
            ExprNode::Float32(y) => {
                match y {
                    Some(n) => 0,
                    None => 0
                }
            }
            ExprNode::Float64(y) => {
                match y {
                    Some(n) => 0,
                    None => 0
                }
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
}
