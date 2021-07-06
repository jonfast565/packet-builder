use crate::models::parsing_models::{ExprNode, PacketExpr, TypeExpr};

pub struct CGenerator {}

impl CGenerator {
    pub fn generate(expr: &PacketExpr) -> String {
        let mut result = String::new();
        result.push_str(&CGenerator::create_headers());
        result.push_str(&CGenerator::create_spacer());
        result.push_str(&CGenerator::create_supporting_functions());
        result.push_str(&CGenerator::create_spacer());
        result.push_str(&CGenerator::build_struct(expr));
        result
    }

    fn create_spacer() -> String {
        "\n".to_string()
    }

    fn create_headers() -> String {
        "\t#include <stdio.h>
        #include <stdlib.h>
        #include <memory.h>
        #include <time.h>
        #include <stdint.h>
        "
        .to_string()
    }

    fn create_supporting_functions() -> String {
        "\tvoid reverse(uint8_t* arr, size_t arr_size) {
            for (size_t low = 0, high = arr_size - 1; low < high; low++, high--) {
                int temp = arr[low];
                arr[low] = arr[high];
                arr[high] = temp;
            }
        }
        "
        .to_string()
    }

    fn build_struct(expr: &PacketExpr) -> String {
        let field_aggregation = expr
            .fields
            .iter()
            .map(|x| match x.expr {
                ExprNode::UnsignedInteger8(y) => {
                    format!("uint8_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                ExprNode::Integer8(y) => {
                    format!("int8_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                ExprNode::UnsignedInteger16(y) => {
                    format!("uint16_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                ExprNode::Integer16(y) => {
                    format!("int16_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                ExprNode::UnsignedInteger32(y) => {
                    format!("uint32_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                ExprNode::Integer32(y) => {
                    format!("int32_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                ExprNode::UnsignedInteger64(y) => {
                    format!("uint64_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                ExprNode::Integer64(y) => {
                    format!("int64_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                ExprNode::Float32(y) => {
                    format!("float {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                ExprNode::Float64(y) => {
                    format!("double {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                _ => "".to_string(),
            })
            .fold(String::new(), |acc, v| format!("{}\t    {}\n", acc, v));

        format!(
            "\ttypedef struct {}\n\t{{\n {} \n\t}} {};\n",
            expr.name, field_aggregation, expr.name
        )
    }

    fn get_array_bounds(expr: Option<usize>) -> String {
        match expr {
            Some(x) => format!("[{}]", x.to_string()),
            None => "".to_string(),
        }
    }

    fn get_field_deserializer(expr: &TypeExpr) -> String {
        let mut result = String::new();
        match expr.expr {
            ExprNode::UnsignedInteger8(y) => {
                match y {
                    Some(y) => {
                        for i in 0..y {
                            result += format!("{}[{}] = {}", expr.id, i, "NULL")
                        }
                    },
                    None => {
                            result += format!("{} = {}", expr.id, "NULL")
                    }
                }
            }
            ExprNode::Integer8(y) => {
                
            }
            ExprNode::UnsignedInteger16(y) => {
                
            }
            ExprNode::Integer16(y) => {
                
            }
            ExprNode::UnsignedInteger32(y) => {
                
            }
            ExprNode::Integer32(y) => {
                
            }
            ExprNode::UnsignedInteger64(y) => {
                
            }
            ExprNode::Integer64(y) => {
                
            }
            ExprNode::Float32(y) => {
                
            }
            ExprNode::Float64(y) => {
                
            },
            ExprNode::MacAddress => {

            }
            _ => (),
        }
        result
    }
}
