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
