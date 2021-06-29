use crate::models::parsing_models::{ExprNode, PacketExpr, TypeExpr};

pub struct CGenerator {}

impl CGenerator {
    pub fn generate(expr: &PacketExpr) -> String {
        let mut result = String::new();
        result.push_str(&CGenerator::build_struct(expr));

        result
    }
    fn build_struct(expr: &PacketExpr) -> String {
        let field_aggregation = expr
            .fields
            .iter()
            .map(|x| match x.expr {
                ExprNode::UnsignedInteger8(y) => format!(
                    "uint8_t {} {};",
                    x.id,
                    CGenerator::get_array_bounds(y)
                ),
                ExprNode::Integer8(y) => format!(
                    "int8_t {} {};",
                    x.id,
                    CGenerator::get_array_bounds(y)
                ),
                ExprNode::UnsignedInteger16(y) => format!(
                    "uint16_t {} {};",
                    x.id,
                    CGenerator::get_array_bounds(y)
                ),
                ExprNode::Integer16(y) => format!(
                    "int16_t {} {};",
                    x.id,
                    CGenerator::get_array_bounds(y)
                ),
                ExprNode::UnsignedInteger32(y) => format!(
                    "uint32_t {} {};",
                    x.id,
                    CGenerator::get_array_bounds(y)
                ),
                ExprNode::Integer32(y) => format!(
                    "int32_t {} {};",
                    x.id,
                    CGenerator::get_array_bounds(y)
                ),
                ExprNode::UnsignedInteger64(y) => format!(
                    "uint64_t {} {};",
                    x.id,
                    CGenerator::get_array_bounds(y)
                ),
                ExprNode::Integer64(y) => format!(
                    "int64_t {} {};",
                    x.id,
                    CGenerator::get_array_bounds(y)
                ),
                _ => "".to_string(),
            })
            .collect();
        field_aggregation
    }

    fn get_array_bounds(expr: Option<usize>) -> String {
        match expr {
            Some(x) => format!("[{}]", x.to_string()),
            None => "".to_string(),
        }
    }
}
