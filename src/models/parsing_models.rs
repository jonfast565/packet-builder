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
    pub fn get_length_bytes(&self) -> usize {
        match self {
            ExprNode::UnsignedInteger8(y) => {
                match y {
                    Some(n) => *n,
                    None => 1
                }
            }
            ExprNode::Integer8(y) => {
                match y {
                    Some(n) => *n,
                    None => 1
                }
            }
            ExprNode::UnsignedInteger16(y) => {
                match y {
                    Some(n) => n * 2,
                    None => 2
                }
            }
            ExprNode::Integer16(y) => {
                match y {
                    Some(n) => n * 2,
                    None => 2
                }
            }
            ExprNode::UnsignedInteger32(y) => {
                match y {
                    Some(n) => n * 4,
                    None => 4
                }
            }
            ExprNode::Integer32(y) => {
                match y {
                    Some(n) => n * 4,
                    None => 4
                }
            }
            ExprNode::UnsignedInteger64(y) => {
                match y {
                    Some(n) => n * 8,
                    None => 8
                }
            }
            ExprNode::Integer64(y) => {
                match y {
                    Some(n) => n * 8,
                    None => 8
                }
            }
            ExprNode::Float32(y) => {
                match y {
                    Some(n) => n * 4,
                    None => 4
                }
            }
            ExprNode::Float64(y) => {
                match y {
                    Some(n) => n * 8,
                    None => 8
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
