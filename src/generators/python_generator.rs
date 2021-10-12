use crate::models::parsing_models::{ExprNode, PacketExpr, TypeExpr};

pub struct PythonGenerator {}

impl PythonGenerator {
    pub fn generate(expr: &Vec<PacketExpr>) -> String {
        let mut result = String::new();
        for exp in expr {
            result.push_str(&PythonGenerator::build_struct(&exp, false));
            result.push_str(&PythonGenerator::create_serialization_functions(&exp));
        }
        result
    }

    fn create_serialization_functions(expr: &PacketExpr) -> String {
        format!(
        "
        def serialize(packet, verbose):
        \t{}

        def deserialize(data, verbose):
        \t{}

        def main():
        \tprint(\"-- Packet Tester --\");
        ",
            &PythonGenerator::create_serializers(expr),
            &PythonGenerator::create_deserializers(expr)
        )
        .to_string()
    }

    fn build_struct(expr: &PacketExpr, just_fields: bool) -> String {
        let field_aggregation = expr
            .fields
            .iter()
            .map(|x| match x.expr {
                ExprNode::UnsignedInteger8(y) => {
                    format!("self.{} = {}", x.id, match y { Some(_) => "[]", None => "0"})
                }
                ExprNode::Integer8(y) => {
                    format!("self.{} = {}", x.id, match y { Some(_) => "[]", None => "0"})
                }
                ExprNode::UnsignedInteger16(y) => {
                    format!("self.{} = {}", x.id, match y { Some(_) => "[]", None => "0"})
                }
                ExprNode::Integer16(y) => {
                    format!("self.{} = {}", x.id, match y { Some(_) => "[]", None => "0"})
                }
                ExprNode::UnsignedInteger32(y) => {
                    format!("self.{} = {}", x.id, match y { Some(_) => "[]", None => "0"})
                }
                ExprNode::Integer32(y) => {
                    format!("self.{} = {}", x.id, match y { Some(_) => "[]", None => "0"})
                }
                ExprNode::UnsignedInteger64(y) => {
                    format!("self.{} = {}", x.id, match y { Some(_) => "[]", None => "0"})
                }
                ExprNode::Integer64(y) => {
                    format!("self.{} = {}", x.id, match y { Some(_) => "[]", None => "0"})
                }
                ExprNode::Float32(y) => {
                    format!("self.{} = {}", x.id, match y { Some(_) => "[]", None => "0"})
                }
                ExprNode::Float64(y) => {
                    format!("self.{} = {}", x.id, match y { Some(_) => "[]", None => "0"})
                }
                _ => "".to_string(),
            })
            .fold(String::new(), |acc, v| format!("{}\t    {}\n", acc, v));

        if !just_fields {
            format!(
                "\tclass {}: \ndef __init__(self):\n\t\t {} \n\t \n\n",
                expr.name, field_aggregation
            )
        } else {
            format!("{}", field_aggregation)
        }
    }

    fn create_deserializers(expr: &PacketExpr) -> String {
        let mut result = String::new();
        let mut counter = 0;
        for field in &expr.fields {
            result.push_str(&PythonGenerator::get_field_deserializer(field, &mut counter));
        }
        result
    }

    fn create_serializers(expr: &PacketExpr) -> String {
        let mut result = String::new();
        let mut counter = 0;
        for field in &expr.fields {
            result.push_str(&PythonGenerator::get_field_serializer(field, &mut counter));
        }
        result
    }

    fn get_field_serializer(expr: &TypeExpr, position: &mut usize) -> String {
        let mut result = String::new();
        match expr.expr {
            ExprNode::UnsignedInteger8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t{};\n",
                            &PythonGenerator::get_8bit_conversion_serialization_array(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                                i
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &PythonGenerator::get_8bit_conversion_serialization(
                            &"data".to_string(),
                            &expr.id,
                            *position,
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t{};\n",
                            &PythonGenerator::get_8bit_conversion_serialization_array(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                                i
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &PythonGenerator::get_8bit_conversion_serialization(
                            &"data".to_string(),
                            &expr.id,
                            *position,
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t{};\n",
                            &PythonGenerator::get_16bit_conversion_serialization_array(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                                i
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &PythonGenerator::get_16bit_conversion_serialization(
                            &"data".to_string(),
                            &expr.id,
                            *position,
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t{};\n",
                            &PythonGenerator::get_16bit_conversion_serialization_array(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                                i
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &PythonGenerator::get_16bit_conversion_serialization(
                            &"data".to_string(),
                            &expr.id,
                            *position,
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t{};\n",
                            &PythonGenerator::get_32bit_conversion_serialization_array(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                                i
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &PythonGenerator::get_32bit_conversion_serialization(
                            &"data".to_string(),
                            &expr.id,
                            *position,
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t{};\n",
                            &PythonGenerator::get_32bit_conversion_serialization_array(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                                i
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &PythonGenerator::get_32bit_conversion_serialization(
                            &"data".to_string(),
                            &expr.id,
                            *position,
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t{};\n",
                            &PythonGenerator::get_64bit_conversion_serialization_array(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                                i
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &PythonGenerator::get_32bit_conversion_serialization(
                            &"data".to_string(),
                            &expr.id,
                            *position,
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t{};\n",
                            &PythonGenerator::get_64bit_conversion_serialization_array(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                                i
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &PythonGenerator::get_64bit_conversion_serialization(
                            &"data".to_string(),
                            &expr.id,
                            *position,
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Float32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t{};\n",
                            &PythonGenerator::get_32bit_conversion_serialization_array(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                                i
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &PythonGenerator::get_32bit_conversion_serialization(
                            &"data".to_string(),
                            &expr.id,
                            *position,
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Float64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\t{};\n",
                            &PythonGenerator::get_64bit_conversion_serialization_array(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                                i
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &PythonGenerator::get_64bit_conversion_serialization(
                            &"data".to_string(),
                            &expr.id,
                            *position,
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::MacAddress => {
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
            ExprNode::UnsignedInteger8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tpacket.{}[{}] = {};\n",
                            expr.id,
                            i,
                            PythonGenerator::get_8bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = (u8)({});\n",
                        expr.id,
                        PythonGenerator::get_8bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tpacket.{}[{}] = (i8)({});\n",
                            expr.id,
                            i,
                            PythonGenerator::get_8bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = (i8)({});\n",
                        expr.id,
                        PythonGenerator::get_8bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tpacket.{}[{}] = (u16)({});\n",
                            expr.id,
                            i,
                            PythonGenerator::get_16bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = (u16)({});\n",
                        expr.id,
                        PythonGenerator::get_16bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tpacket.{}[{}] = (i16)({});\n",
                            expr.id,
                            i,
                            PythonGenerator::get_16bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = (i16)({});\n",
                        expr.id,
                        PythonGenerator::get_16bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tpacket.{}[{}] = (u32)({});\n",
                            expr.id,
                            i,
                            PythonGenerator::get_32bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = (u32)({});\n",
                        expr.id,
                        PythonGenerator::get_32bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tpacket.{}[{}] = (i32)({});\n",
                            expr.id,
                            i,
                            PythonGenerator::get_32bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = (i32)({});\n",
                        expr.id,
                        PythonGenerator::get_32bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tpacket.{}[{}] = (u64)({});\n",
                            expr.id,
                            i,
                            PythonGenerator::get_64bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = (u64)({});\n",
                        expr.id,
                        PythonGenerator::get_64bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tpacket.{}[{}] = (i64)({});\n",
                            expr.id,
                            i,
                            PythonGenerator::get_64bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = (i64)({});\n",
                        expr.id,
                        PythonGenerator::get_64bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Float32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tpacket.{}[{}] = (f32)({});\n",
                            expr.id,
                            i,
                            PythonGenerator::get_32bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = (f32)({});\n",
                        expr.id,
                        PythonGenerator::get_32bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Float64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tpacket.{}[{}] = (f64)({});\n",
                            expr.id,
                            i,
                            PythonGenerator::get_64bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = (f64)({});\n",
                        expr.id,
                        PythonGenerator::get_64bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::MacAddress => {
                result.push_str(&format!("// Not implemented {};\n", &"data".to_string()));
                *position += expr.expr.get_type_length_bytes();
            }
            _ => (),
        }
        result
    }

    fn get_8bit_conversion_serialization(
        result_variable: &String,
        data_variable: &String,
        position: usize,
    ) -> String {
        format!("{}[{}] = {}", result_variable, position, data_variable)
    }

    fn get_16bit_conversion_serialization(
        result_variable: &String,
        data_variable: &String,
        position: usize,
    ) -> String {
        format!(
            "{}[{}] = {}\n",
            result_variable, position, data_variable
        ) + &format!(
            "\t{}[{}] = {} >> 8",
            result_variable,
            position + 1,
            data_variable
        )
    }

    fn get_32bit_conversion_serialization(
        result_variable: &String,
        data_variable: &String,
        position: usize,
    ) -> String {
        format!(
            "{}[{}] = {}\n",
            result_variable, position, data_variable
        ) + &format!(
            "\t{}[{}] = {} >> 8\n",
            result_variable,
            position + 1,
            data_variable
        ) + &format!(
            "\t{}[{}] = {} >> 16\n",
            result_variable,
            position + 2,
            data_variable
        ) + &format!(
            "\t{}[{}] = {} >> 24",
            result_variable,
            position + 3,
            data_variable
        )
    }

    fn get_64bit_conversion_serialization(
        result_variable: &String,
        data_variable: &String,
        position: usize,
    ) -> String {
        format!(
            "{}[{}] = {}\n",
            result_variable, position, data_variable
        ) + &format!(
            "\t{}[{}] = {} >> 8\n",
            result_variable,
            position + 1,
            data_variable
        ) + &format!(
            "\t{}[{}] = {} >> 16\n",
            result_variable,
            position + 2,
            data_variable
        ) + &format!(
            "\t{}[{}] = {} >> 24\n",
            result_variable,
            position + 3,
            data_variable
        ) + &format!(
            "\t{}[{}] = {} >> 32\n",
            result_variable,
            position + 4,
            data_variable
        ) + &format!(
            "\t{}[{}] = {} >> 40\n",
            result_variable,
            position + 5,
            data_variable
        ) + &format!(
            "\t{}[{}] = {} >> 48\n",
            result_variable,
            position + 6,
            data_variable
        ) + &format!(
            "\t{}[{}] = {} >> 56",
            result_variable,
            position + 7,
            data_variable
        )
    }

    fn get_8bit_conversion_serialization_array(
        result_variable: &String,
        data_variable: &String,
        position: usize,
        i: usize,
    ) -> String {
        format!("{}[{}] = {}[{}]", result_variable, position, data_variable, i)
    }

    fn get_16bit_conversion_serialization_array(
        result_variable: &String,
        data_variable: &String,
        position: usize,
        i: usize
    ) -> String {
        format!(
            "{}[{}] = {}[{}];\n",
            result_variable, position, data_variable, i
        ) + &format!(
            "\t{}[{}] = {}[{}] >> 8",
            result_variable,
            position + 1,
            data_variable, i
        )
    }

    fn get_32bit_conversion_serialization_array(
        result_variable: &String,
        data_variable: &String,
        position: usize,
        i: usize
    ) -> String {
        format!(
            "{}[{}] = {}[{}]\n",
            result_variable, position, data_variable, i
        ) + &format!(
            "\t{}[{}] = {}[{}] >> 8\n",
            result_variable,
            position + 1,
            data_variable, i
        ) + &format!(
            "\t{}[{}] = {}[{}] >> 16\n",
            result_variable,
            position + 2,
            data_variable, i
        ) + &format!(
            "\t{}[{}] = {}[{}] >> 24",
            result_variable,
            position + 3,
            data_variable, i
        )
    }

    fn get_64bit_conversion_serialization_array(
        result_variable: &String,
        data_variable: &String,
        position: usize,
        i: usize
    ) -> String {
        format!(
            "{}[{}] = {}[{}]\n",
            result_variable, position, data_variable, i
        ) + &format!(
            "\t{}[{}] = {}[{}] >> 8\n",
            result_variable,
            position + 1,
            data_variable,
            i
        ) + &format!(
            "\t{}[{}] = {}[{}] >> 16\n",
            result_variable,
            position + 2,
            data_variable,
            i
        ) + &format!(
            "\t{}[{}] = {}[{}] >> 24\n",
            result_variable,
            position + 3,
            data_variable,
            i
        ) + &format!(
            "\t{}[{}] = {}[{}] >> 32\n",
            result_variable,
            position + 4,
            data_variable,
            i
        ) + &format!(
            "\t{}[{}] = {}[{}] >> 40\n",
            result_variable,
            position + 5,
            data_variable,
            i
        ) + &format!(
            "\t{}[{}] = {}[{}] >> 48\n",
            result_variable,
            position + 6,
            data_variable,
            i
        ) + &format!(
            "\t{}[{}] = {}[{}] >> 56",
            result_variable,
            position + 7,
            data_variable,
            i
        )
    }

    fn get_8bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!("{}[{}]", variable, position)
    }

    fn get_16bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!(
            "{}[{}] | {}[{}] << 8",
            variable,
            position + 1,
            variable,
            position,
        )
    }

    fn get_32bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!(
            "{}[{}] | {}[{}] << 8 | {}[{}] << 16 | {}[{}] << 24",
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
            "{}[{}] | {}[{}] << 8 | {}[{}] << 16 | {}[{}] << 24 | {}[{}] << 32 | {}[{}] << 40 | {}[{}] << 48 | {}[{}] << 56",
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
