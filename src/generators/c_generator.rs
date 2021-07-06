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
        result.push_str(&CGenerator::create_serialization_functions(expr));
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

    fn create_serialization_functions(expr: &PacketExpr) -> String {
        format!(
            "\tvoid serialize(uint8_t* data, {}** packet, int verbose) {{
            uint8_t* result = (uint8_t*) calloc({{TotalLength}}, sizeof(uint8_t));
            memset(result, 0, {{TotalLength}});
            size_t packet_counter = 0;
            {}
        }}

        void deserialize({}* packet, uint8_t** data,  int verbose) {{
            size_t packet_counter = 0;
            {}
        }}
        ",
            expr.name,
            &CGenerator::create_serializers(expr),
            expr.name,
            &CGenerator::create_deserializers(expr)
        )
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
            "\ttypedef struct {} {{\n {} \n\t}} {};\n\n",
            expr.name, field_aggregation, expr.name
        )
    }

    fn get_array_bounds(expr: Option<usize>) -> String {
        match expr {
            Some(x) => format!("[{}]", x.to_string()),
            None => "".to_string(),
        }
    }

    fn create_deserializers(expr: &PacketExpr) -> String {
        String::new()
    }

    fn create_serializers(expr: &PacketExpr) -> String {
        String::new()
    }

    fn get_field_deserializer(expr: &TypeExpr) -> String {
        let mut result = String::new();
        match expr.expr {
            ExprNode::UnsignedInteger8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!("{}[{}] = {}", expr.id, i, "NULL"))
                    }
                }
                None => result.push_str(&format!("{} = {}", expr.id, "NULL")),
            },
            ExprNode::Integer8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!("{}[{}] = {}", expr.id, i, "NULL"))
                    }
                }
                None => result.push_str(&format!("{} = {}", expr.id, "NULL")),
            },
            ExprNode::UnsignedInteger16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!("{}[{}] = {}", expr.id, i, "NULL"))
                    }
                }
                None => result.push_str(&format!("{} = {}", expr.id, "NULL")),
            },
            ExprNode::Integer16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!("{}[{}] = {}", expr.id, i, "NULL"))
                    }
                }
                None => result.push_str(&format!("{} = {}", expr.id, "NULL")),
            },
            ExprNode::UnsignedInteger32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!("{}[{}] = {}", expr.id, i, "NULL"))
                    }
                }
                None => result.push_str(&format!("{} = {}", expr.id, "NULL")),
            },
            ExprNode::Integer32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!("{}[{}] = {}", expr.id, i, "NULL"))
                    }
                }
                None => result.push_str(&format!("{} = {}", expr.id, "NULL")),
            },
            ExprNode::UnsignedInteger64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!("{}[{}] = {}", expr.id, i, "NULL"))
                    }
                }
                None => result.push_str(&format!("{} = {}", expr.id, "NULL")),
            },
            ExprNode::Integer64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!("{}[{}] = {}", expr.id, i, "NULL"))
                    }
                }
                None => result.push_str(&format!("{} = {}", expr.id, "NULL")),
            },
            ExprNode::Float32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!("{}[{}] = {}", expr.id, i, "NULL"))
                    }
                }
                None => result.push_str(&format!("{} = {}", expr.id, "NULL")),
            },
            ExprNode::Float64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!("{}[{}] = {}", expr.id, i, "NULL"))
                    }
                }
                None => result.push_str(&format!("{} = {}", expr.id, "NULL")),
            },
            ExprNode::MacAddress => result.push_str(&format!("// Not implemented {}", expr.id)),
            _ => (),
        }
        result
    }
}
