use crate::models::parsing_models::{ExprNode, PacketExpr, TypeExpr};

pub struct RustGenerator {}

impl RustGenerator {
    pub fn generate(expr: &PacketExpr) -> String {
        let mut result = String::new();
        result.push_str(&RustGenerator::create_headers());
        result.push_str(&RustGenerator::create_spacer());
        result.push_str(&RustGenerator::create_spacer());
        result.push_str(&RustGenerator::build_struct(expr, false));
        result.push_str(&RustGenerator::create_serialization_functions(expr));
        result
    }

    fn create_spacer() -> String {
        "\n".to_string()
    }

    fn create_headers() -> String {
        "\t
        use std::io::Cursor;
        use byteorder::{ByteOrder, BigEndian, ReadBytesExt, WriteBytesExt};
        "
        .to_string()
    }

    fn create_serialization_functions(expr: &PacketExpr) -> String {
        format!(
            "\tfn serialize(p: {}) -> Vec<u8> {{
            let mut data: Vec<u8> = vec![];
            {}
            data
        }}

        fn deserialize(data: &[u8]) -> {} {{
            {}
            {} {{
                {}
            }}
        }}

        fn main() {{
            
        }}
        ",
            expr.name,
            &RustGenerator::create_serializers(expr),
            expr.name,
            &RustGenerator::create_deserializers(expr),
            expr.name,
            &RustGenerator::create_deserializer_builders(expr)
        )
        .to_string()
    }

    fn build_struct(expr: &PacketExpr, just_fields: bool) -> String {
        let field_aggregation = expr
            .fields
            .iter()
            .map(|x| match x.expr {
                ExprNode::UnsignedInteger8(y) => {
                    format!("{}: {},", x.id, RustGenerator::get_array_bounds("u8", y))
                }
                ExprNode::Integer8(y) => {
                    format!("{}: {},", x.id, RustGenerator::get_array_bounds("i8", y))
                }
                ExprNode::UnsignedInteger16(y) => {
                    format!("{}: {},", x.id, RustGenerator::get_array_bounds("u16", y))
                }
                ExprNode::Integer16(y) => {
                    format!("{}: {},", x.id, RustGenerator::get_array_bounds("i16", y))
                }
                ExprNode::UnsignedInteger32(y) => {
                    format!("{}: {},", x.id, RustGenerator::get_array_bounds("u32", y))
                }
                ExprNode::Integer32(y) => {
                    format!("{}: {},", x.id, RustGenerator::get_array_bounds("i32", y))
                }
                ExprNode::UnsignedInteger64(y) => {
                    format!("{}: {},", x.id, RustGenerator::get_array_bounds("u64", y))
                }
                ExprNode::Integer64(y) => {
                    format!("{}: {},", x.id, RustGenerator::get_array_bounds("i64", y))
                }
                ExprNode::Float32(y) => {
                    format!("{}: {},", x.id, RustGenerator::get_array_bounds("f32", y))
                }
                ExprNode::Float64(y) => {
                    format!("{}: {},", x.id, RustGenerator::get_array_bounds("f64", y))
                }
                _ => "".to_string(),
            })
            .fold(String::new(), |acc, v| format!("{}\t    {}\n", acc, v));

        if !just_fields {
            format!(
                "\tpub struct {} {{\n {} \n\t}}\n\n",
                expr.name, field_aggregation
            )
        } else {
            format!("{}", field_aggregation)
        }
    }

    fn get_array_bounds(data_type: &str, expr: Option<usize>) -> String {
        match expr {
            Some(x) => format!("[{}; {}]", data_type, x.to_string()),
            None => format!("{}", data_type.to_string()),
        }
    }

    fn create_deserializers(expr: &PacketExpr) -> String {
        let mut result = String::new();
        let mut counter = 0;
        for field in &expr.fields {
            result.push_str(&RustGenerator::get_field_deserializer(field, &mut counter));
        }
        result
    }

    fn create_deserializer_builders(expr: &PacketExpr) -> String {
        let mut result = String::new();
        for field in &expr.fields {
            result.push_str(&RustGenerator::get_field_serializer_builder(field));
        }
        result
    }

    fn get_field_serializer_builder(expr: &TypeExpr) -> String {
        let mut result = String::new();
        match expr.expr {
            ExprNode::UnsignedInteger8(y)
            | ExprNode::Integer8(y)
            | ExprNode::UnsignedInteger16(y)
            | ExprNode::Integer16(y)
            | ExprNode::UnsignedInteger32(y)
            | ExprNode::Integer32(y)
            | ExprNode::UnsignedInteger64(y)
            | ExprNode::Integer64(y)
            | ExprNode::Float32(y)
            | ExprNode::Float64(y) => {
                match y {
                    Some(y) => {
                        let mut array = String::new();
                        for i in 0..y {
                            array.push_str(&format!("{}_{}", expr.id, i).to_string());
                            if i < y - 1 {
                                array.push_str(", ");
                            }
                        }
                        result.push_str(&format!("{}: [{}],\n", expr.id, array).to_string());
                    },
                    None => {
                        result.push_str(&format!("{}: {},\n", expr.id, expr.id).to_string());
                    }
                }
            }
            ExprNode::MacAddress => {}
            _ => (),
        };

        result
    }

    fn create_serializers(expr: &PacketExpr) -> String {
        let mut result = String::new();
        let mut counter = 0;
        for field in &expr.fields {
            result.push_str(&RustGenerator::get_field_serializer(field, &mut counter));
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
                            "\tdata.write_{}::<BigEndian>(p.{}[{}]).unwrap();\n",
                            &"u8".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(p.{}).unwrap();\n",
                        &"u8".to_string(),
                        expr.id
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tdata.write_{}::<BigEndian>(p.{}[{}]).unwrap();\n",
                            &"i8".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(p.{}).unwrap();\n",
                        &"i8".to_string(),
                        expr.id
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tdata.write_{}::<BigEndian>(p.{}[{}]).unwrap();\n",
                            &"u16".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(p.{}).unwrap();\n",
                        &"u16".to_string(),
                        expr.id
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tdata.write_{}::<BigEndian>(p.{}[{}]).unwrap();\n",
                            &"i16".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(p.{}).unwrap();\n",
                        &"i16".to_string(),
                        expr.id
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tdata.write_{}::<BigEndian>(p.{}[{}]).unwrap();\n",
                            &"u32".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(p.{}).unwrap();\n",
                        &"u32".to_string(),
                        expr.id
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tdata.write_{}::<BigEndian>(p.{}[{}]).unwrap();\n",
                            &"i32".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(p.{}).unwrap();\n",
                        &"i32".to_string(),
                        expr.id
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tdata.write_{}::<BigEndian>(p.{}[{}]).unwrap();\n",
                            &"u64".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(p.{}).unwrap();\n",
                        &"u64".to_string(),
                        expr.id
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tdata.write_{}::<BigEndian>(p.{}[{}]).unwrap();\n",
                            &"i64".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(p.{}).unwrap();\n",
                        &"i64".to_string(),
                        expr.id
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Float32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tdata.write_{}::<BigEndian>(p.{}[{}]).unwrap();\n",
                            &"f32".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(p.{}).unwrap();\n",
                        &"f32".to_string(),
                        expr.id
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Float64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tdata.write_{}::<BigEndian>(p.{}[{}]).unwrap();\n",
                            &"f64".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(p.{}).unwrap();\n",
                        &"f64".to_string(),
                        expr.id
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
                            "\tlet {}_{} = {};\n",
                            expr.id,
                            i,
                            RustGenerator::get_conversion_deserialization(
                                &"data".to_string(),
                                &"u8".to_string(),
                                *position,
                                1
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tlet {} = {};\n",
                        expr.id,
                        RustGenerator::get_conversion_deserialization(
                            &"data".to_string(),
                            &"u8".to_string(),
                            *position,
                            1
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tlet {}_{} = {};\n",
                            expr.id,
                            i,
                            RustGenerator::get_conversion_deserialization(
                                &"data".to_string(),
                                &"i8".to_string(),
                                *position,
                                1
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tlet {} = {};\n",
                        expr.id,
                        RustGenerator::get_conversion_deserialization(
                            &"data".to_string(),
                            &"i8".to_string(),
                            *position,
                            1
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tlet {}_{} = {};\n",
                            expr.id,
                            i,
                            RustGenerator::get_conversion_deserialization(
                                &"data".to_string(),
                                &"u16".to_string(),
                                *position,
                                2
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tlet {} = {};\n",
                        expr.id,
                        RustGenerator::get_conversion_deserialization(
                            &"data".to_string(),
                            &"u16".to_string(),
                            *position,
                            2
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tlet {}_{} = {};\n",
                            expr.id,
                            i,
                            RustGenerator::get_conversion_deserialization(
                                &"data".to_string(),
                                &"i16".to_string(),
                                *position,
                                2
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tlet {} = {};\n",
                        expr.id,
                        RustGenerator::get_conversion_deserialization(
                            &"data".to_string(),
                            &"i16".to_string(),
                            *position,
                            2
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tlet {}_{} = {};\n",
                            expr.id,
                            i,
                            RustGenerator::get_conversion_deserialization(
                                &"data".to_string(),
                                &"u32".to_string(),
                                *position,
                                4
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tlet {} = {};\n",
                        expr.id,
                        RustGenerator::get_conversion_deserialization(
                            &"data".to_string(),
                            &"u32".to_string(),
                            *position,
                            4
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tlet {}_{} = {};\n",
                            expr.id,
                            i,
                            RustGenerator::get_conversion_deserialization(
                                &"data".to_string(),
                                &"i32".to_string(),
                                *position,
                                4
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tlet {} = {};\n",
                        expr.id,
                        RustGenerator::get_conversion_deserialization(
                            &"data".to_string(),
                            &"i32".to_string(),
                            *position,
                            4
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tlet {}_{} = {};\n",
                            expr.id,
                            i,
                            RustGenerator::get_conversion_deserialization(
                                &"data".to_string(),
                                &"u64".to_string(),
                                *position,
                                8
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tlet {} = {};\n",
                        expr.id,
                        RustGenerator::get_conversion_deserialization(
                            &"data".to_string(),
                            &"u64".to_string(),
                            *position,
                            8
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tlet {}_{} = {};\n",
                            expr.id,
                            i,
                            RustGenerator::get_conversion_deserialization(
                                &"data".to_string(),
                                &"i64".to_string(),
                                *position,
                                8
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tlet {} = {};\n",
                        expr.id,
                        RustGenerator::get_conversion_deserialization(
                            &"data".to_string(),
                            &"i64".to_string(),
                            *position,
                            8
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Float32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tlet {}_{} = {};\n",
                            expr.id,
                            i,
                            RustGenerator::get_conversion_deserialization(
                                &"data".to_string(),
                                &"f32".to_string(),
                                *position,
                                4
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tlet {} = {};\n",
                        expr.id,
                        RustGenerator::get_conversion_deserialization(
                            &"data".to_string(),
                            &"f32".to_string(),
                            *position,
                            4
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Float64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tlet {}_{} = {};\n",
                            expr.id,
                            i,
                            RustGenerator::get_conversion_deserialization(
                                &"data".to_string(),
                                &"f64".to_string(),
                                *position,
                                8
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tlet {} = {};\n",
                        expr.id,
                        RustGenerator::get_conversion_deserialization(
                            &"data".to_string(),
                            &"f64".to_string(),
                            *position,
                            8
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

    fn get_conversion_deserialization(
        variable: &String,
        data_type: &String,
        position: usize,
        data_byte_size: usize,
    ) -> String {
        if data_type == "u8" {
            format!("{}[{}]", variable, position)
        } else {
            format!(
                "BigEndian::read_{}(&{}[{}..{}])",
                data_type,
                variable,
                position,
                position + data_byte_size
            )
        }
    }
}
