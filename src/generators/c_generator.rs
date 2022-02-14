use crate::models::parsing_models::{ExprNode, PacketExpr, TypeExpr, PacketExprList, TypeNode};

pub struct CGenerator {}

impl CGenerator {
    pub fn generate(expr: &PacketExprList) -> String {
        let mut result = String::new();
        result.push_str(&CGenerator::create_headers());
        result.push_str(&CGenerator::create_spacer());
        result.push_str(&CGenerator::create_supporting_functions());
        result.push_str(&CGenerator::create_spacer());
        for exp in &expr.packets {
            result.push_str(&CGenerator::build_struct(&exp, false));
            result.push_str(&CGenerator::create_serialization_functions(&exp));
        }
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
            "\tvoid serialize(uint8_t** data, {}* packet, int verbose) {{
            *data = (uint8_t*) calloc({}, sizeof(uint8_t));
            memset(*data, 0, {});
            {}
        }}

        void deserialize({}** packet, uint8_t* data, int verbose) {{
            *packet = ({}*) malloc(sizeof({}));
            {}
        }}

        void main(int argc, char** argv) {{
            
        }}
        ",
            expr.name,
            expr.get_total_length(),
            expr.get_total_length(),
            &CGenerator::create_serializers(expr),
            expr.name,
            expr.name,
            expr.name,
            &CGenerator::create_deserializers(expr)
        )
        .to_string()
    }

    fn build_struct(expr: &PacketExpr, just_fields: bool) -> String {
        let field_aggregation = expr
            .fields
            .iter()
            .map(|x| match x.expr {
                TypeNode::UnsignedInteger8(y) => {
                    format!("uint8_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                TypeNode::Integer8(y) => {
                    format!("int8_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                TypeNode::UnsignedInteger16(y) => {
                    format!("uint16_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                TypeNode::Integer16(y) => {
                    format!("int16_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                TypeNode::UnsignedInteger32(y) => {
                    format!("uint32_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                TypeNode::Integer32(y) => {
                    format!("int32_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                TypeNode::UnsignedInteger64(y) => {
                    format!("uint64_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                TypeNode::Integer64(y) => {
                    format!("int64_t {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                TypeNode::Float32(y) => {
                    format!("float {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                TypeNode::Float64(y) => {
                    format!("double {}{};", x.id, CGenerator::get_array_bounds(y))
                }
                _ => "".to_string(),
            })
            .fold(String::new(), |acc, v| format!("{}\t    {}\n", acc, v));

        if !just_fields {
            format!(
                "\ttypedef struct {} {{\n {} \n\t}} {};\n\n",
                expr.name, field_aggregation, expr.name
            )
        } else {
            format!("{}", field_aggregation)
        }
    }

    fn get_array_bounds(expr: Option<usize>) -> String {
        match expr {
            Some(x) => format!("[{}]", x.to_string()),
            None => "".to_string(),
        }
    }

    fn create_deserializers(expr: &PacketExpr) -> String {
        let mut result = String::new();
        let mut counter = 0;
        for field in &expr.fields {
            result.push_str(&CGenerator::get_field_deserializer(field, &mut counter));
        }
        result
    }

    fn create_serializers(expr: &PacketExpr) -> String {
        let mut result = String::new();
        let mut counter = 0;
        for field in &expr.fields {
            result.push_str(&CGenerator::get_field_serializer(field, &mut counter));
        }
        result
    }

    fn get_field_serializer(expr: &TypeExpr, position: &mut usize) -> String {
        let mut result = String::new();
        match expr.expr {
            TypeNode::UnsignedInteger8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], &packet->{}[{}], {});\n",
                            i,
                            expr.id,
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], &packet->{}, {});\n",
                        *position,
                        expr.id,
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], &packet->{}[{}], {});\n",
                            i,
                            expr.id,
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], &packet->{}, {});\n",
                        *position,
                        expr.id,
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], &packet->{}[{}], {});\n",
                            i,
                            expr.id,
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], &packet->{}, {});\n",
                        *position,
                        expr.id,
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], &packet->{}[{}], {});\n",
                            i,
                            expr.id,
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], &packet->{}, {});\n",
                        *position,
                        expr.id,
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], &packet->{}[{}], {});\n",
                            i,
                            expr.id,
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], &packet->{}, {});\n",
                        *position,
                        expr.id,
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], &packet->{}[{}], {});\n",
                            i,
                            expr.id,
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], &packet->{}, {});\n",
                        *position,
                        expr.id,
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], &packet->{}[{}], {});\n",
                            i,
                            expr.id,
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], &packet->{}, {});\n",
                        *position,
                        expr.id,
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], &packet->{}[{}], {});\n",
                            i,
                            expr.id,
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], &packet->{}, {});\n",
                        *position,
                        expr.id,
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Float32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], &packet->{}[{}], {});\n",
                            i,
                            expr.id,
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], &packet->{}, {});\n",
                        *position,
                        expr.id,
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Float64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], &packet->{}[{}], {});\n",
                            i,
                            expr.id,
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], &packet->{}, {});\n",
                        *position,
                        expr.id,
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::MacAddress => {
                result.push_str(&format!("// Not implemented {};\n", &"data".to_string()));
                *position += expr.expr.get_type_length_bytes();
            }
            _ => (),
        }
        result
    }

    fn get_field_deserializer(expr: &TypeExpr, position: &mut usize) -> String {
        let mut result = String::new();
        match expr.expr {
            TypeNode::UnsignedInteger8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t(*packet)->{}[{}] = {};\n",
                            expr.id,
                            i,
                            CGenerator::get_8bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t(*packet)->{} = (uint8_t)({});\n",
                        expr.id,
                        CGenerator::get_8bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t(*packet)->{}[{}] = (int8_t)({});\n",
                            expr.id,
                            i,
                            CGenerator::get_8bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t(*packet)->{} = (int8_t)({});\n",
                        expr.id,
                        CGenerator::get_8bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t(*packet)->{}[{}] = (uint16_t)({});\n",
                            expr.id,
                            i,
                            CGenerator::get_16bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t(*packet)->{} = (uint16_t)({});\n",
                        expr.id,
                        CGenerator::get_16bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t(*packet)->{}[{}] = (int16_t)({});\n",
                            expr.id,
                            i,
                            CGenerator::get_16bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t(*packet)->{} = (int16_t)({});\n",
                        expr.id,
                        CGenerator::get_16bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t(*packet)->{}[{}] = (uint32_t)({});\n",
                            expr.id,
                            i,
                            CGenerator::get_32bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t(*packet)->{} = (uint32_t)({});\n",
                        expr.id,
                        CGenerator::get_32bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t(*packet)->{}[{}] = (int32_t)({});\n",
                            expr.id,
                            i,
                            CGenerator::get_32bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t(*packet)->{} = (int32_t)({});\n",
                        expr.id,
                        CGenerator::get_32bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t(*packet)->{}[{}] = (uint64_t)({});\n",
                            expr.id,
                            i,
                            CGenerator::get_64bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t(*packet)->{} = (uint64_t)({});\n",
                        expr.id,
                        CGenerator::get_64bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t(*packet)->{}[{}] = (int64_t)({});\n",
                            expr.id,
                            i,
                            CGenerator::get_64bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t(*packet)->{} = (int64_t)({});\n",
                        expr.id,
                        CGenerator::get_64bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Float32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t(*packet)->{}[{}] = (float)({});\n",
                            expr.id,
                            i,
                            CGenerator::get_32bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t(*packet)->{} = (float)({});\n",
                        expr.id,
                        CGenerator::get_32bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Float64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t(*packet)->{}[{}] = (double)({});\n",
                            expr.id,
                            i,
                            CGenerator::get_64bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t(*packet)->{} = (double)({});\n",
                        expr.id,
                        CGenerator::get_64bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::MacAddress => {
                result.push_str(&format!("// Not implemented {};\n", &"data".to_string()));
                *position += expr.expr.get_type_length_bytes();
            }
            _ => (),
        }
        result
    }

    fn get_8bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!("(uint8_t) {}[{}]", variable, position)
    }

    fn get_16bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!(
            "(uint16_t) {}[{}] | 
                ((uint16_t) {}[{}] << 8)",
            variable,
            position + 1,
            variable,
            position,
        )
    }

    fn get_32bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!(
            "(uint32_t) {}[{}] |
                ((uint32_t) {}[{}] << 8) | 
                ((uint32_t) {}[{}] << 16) |
                ((uint32_t) {}[{}] << 24)",
            variable,
            position + 3,
            variable,
            position + 2,
            variable,
            position + 1,
            variable,
            position
        )
    }

    fn get_64bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!(
            "(uint64_t) {}[{}] |
                ((uint64_t) {}[{}] << 8)  | 
                ((uint64_t) {}[{}] << 16) |  
                ((uint64_t) {}[{}] << 24) |
                ((uint64_t) {}[{}] << 32) |
                ((uint64_t) {}[{}] << 40) |
                ((uint64_t) {}[{}] << 48) |
                ((uint64_t) {}[{}] << 56)",
            variable,
            position + 7,
            variable,
            position + 6,
            variable,
            position + 5,
            variable,
            position + 4,
            variable,
            position + 3,
            variable,
            position + 2,
            variable,
            position + 1,
            variable,
            position
        )
    }
}
