use crate::models::parsing_models::{ExprNode, PacketExpr};

pub struct CGenerator {}

impl CGenerator {
    fn build_struct(expr: &PacketExpr) -> String {
        let field_aggregation = expr
            .fields
            .iter()
            .map(|x| match x.expr {
                ExprNode::Integer16(y) => format!(
                    "uint16_t {} {};",
                    x.id,
                    match y {
                        Some(x) => format!("[{}]", x.to_string()),
                        None => "".to_string(),
                    }
                ),
                _ => "".to_string(),
            })
            .collect();
        field_aggregation
    }
}
