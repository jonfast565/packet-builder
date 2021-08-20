use crate::models::parsing_models::{CalculatedField, ExprNode, PacketExpr, TypeExpr};

pub struct RustGenerator {}

impl RustGenerator {
    pub fn generate(expr: &Vec<PacketExpr>) -> String {
        let mut result = String::new();
        result.push_str(&RustGenerator::create_headers());
        result.push_str(&RustGenerator::create_spacer());
        result.push_str(&RustGenerator::create_spacer());
        for exp in expr {
            result.push_str(&RustGenerator::build_struct(&exp, false));
            result.push_str(&RustGenerator::create_serialization_functions(&exp));
        }
        result
    }

    fn create_spacer() -> String {
        "\n".to_string()
    }

    fn create_headers() -> String {
        "\t
        use std::io::Cursor;
        use byteorder::{ByteOrder, LittleEndian, BigEndian, ReadBytesExt, WriteBytesExt};
        use serde::{Serialize, Deserialize};
        "
        .to_string()
    }

    fn create_serialization_functions(expr: &PacketExpr) -> String {
        format!(
            "
        impl {} {{
        pub fn serialize(&self) -> Vec<u8> {{
            let mut data: Vec<u8> = vec![];
            {}
            data
        }}

        pub fn deserialize(data: &[u8]) -> {} {{
            {}
            {} {{
                {}
            }}
        }}


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

        let calc_field_aggregation = expr
            .calculated_fields
            .iter()
            .map(|x| {
                format!(
                    "{}: {},",
                    x.name,
                    RustGenerator::datatype_to_rust_type(x.data_type.clone())
                )
            })
            .fold(String::new(), |acc, v| format!("{}\t    {}\n", acc, v));

        if !just_fields {
            format!(
                "\t#[derive(Debug, Serialize, Deserialize)]
                pub struct {} {{\n {} {}\n\t}}\n\n",
                expr.name, field_aggregation, calc_field_aggregation
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
        for field in &expr.calculated_fields {
            result.push_str(&RustGenerator::get_calculated_field_deserializer(field));
        }
        result
    }

    fn create_deserializer_builders(expr: &PacketExpr) -> String {
        let mut result = String::new();
        for field in &expr.fields {
            result.push_str(&RustGenerator::get_field_deserializer_builder(field));
        }
        for field in &expr.calculated_fields {
            result.push_str(&RustGenerator::get_calculated_field_deserializer_builder(
                field,
            ));
        }
        result
    }

    fn get_calculated_field_deserializer(expr: &CalculatedField) -> String {
        format!(
            "\tlet {} = {};\n",
            expr.name,
            RustGenerator::get_expr_builder(*expr.expr.clone())
        )
    }

    fn get_calculated_field_deserializer_builder(expr: &CalculatedField) -> String {
        format!("\t{}: {},\n", expr.name, expr.name)
    }

    fn get_expr_builder(expr: ExprNode) -> String {
        let mut string_vec = Vec::new();
        match expr {
            ExprNode::UnsignedInteger64Value(value) => {
                string_vec.push(format!("({} as f64)", value.to_string()));
            }
            ExprNode::Integer64Value(value) => {
                string_vec.push(format!("({} as f64)", value.to_string()));
            }
            ExprNode::Float64Value(value) => {
                string_vec.push(value.to_string());
            }
            ExprNode::ValueReference(ident, optional_array_size) => match optional_array_size {
                Some(x) => string_vec.push(format!("({}_{} as f64)", ident, x)),
                None => string_vec.push(format!("({} as f64)", ident.to_string())),
            },
            ExprNode::ParenthesizedExpr(lexpr) => {
                string_vec.push(
                    "(".to_string() + &RustGenerator::get_expr_builder(*lexpr) + &")".to_string(),
                );
            }
            ExprNode::Plus(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" + ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::Minus(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" - ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::Mult(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" * ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::Div(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" / ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::Pow(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" ^ ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::Gt(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" > ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::Lt(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" < ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::Gte(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" >= ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::Lte(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" <= ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::Equals(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" == ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::NotEquals(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" != ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::And(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" && ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::Or(lexpr, rexpr) => {
                string_vec.push(
                    RustGenerator::get_expr_builder(*lexpr)
                        + &" || ".to_string()
                        + &RustGenerator::get_expr_builder(*rexpr),
                );
            }
            ExprNode::GuardExpression(bexpr, texpr, oexpr) => {
                string_vec.push(format!(
                    "if {} {{ {} }} else {{ {} }}",
                    RustGenerator::get_expr_builder(*bexpr),
                    RustGenerator::get_expr_builder(*texpr),
                    RustGenerator::get_expr_builder(*oexpr)
                ));
            }
            ExprNode::SumOf(lexpr) => {
                panic!("Aggregate expressions not implemented")
            }
            ExprNode::ProductOf(lexpr) => {
                panic!("Aggregate expressions not implemented")
            }
            ExprNode::ActivationRecord(function_name, parameters) => {
                if function_name == "sqrt" {
                    string_vec.push(
                        "(".to_string()
                            + &RustGenerator::get_expr_builder(parameters[0].clone())
                            + " as f64).sqrt()",
                    )
                } else if function_name == "min" || function_name == "max" {
                    string_vec.push(
                        "(".to_string()
                            + &RustGenerator::get_expr_builder(parameters[0].clone())
                            + "."
                            + &function_name
                            + "("
                            + &RustGenerator::get_expr_builder(parameters[1].clone())
                            + "))",
                    )
                }
            }
            _ => {
                panic!("Unsupported statement type")
            }
        }
        string_vec.join(" ")
    }

    fn get_field_deserializer_builder(expr: &TypeExpr) -> String {
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
            | ExprNode::Float64(y) => match y {
                Some(y) => {
                    let mut array = String::new();
                    for i in 0..y {
                        array.push_str(&format!("{}_{}", expr.id, i).to_string());
                        if i < y - 1 {
                            array.push_str(", ");
                        }
                    }
                    result.push_str(&format!("{}: [{}],\n", expr.id, array).to_string());
                }
                None => {
                    result.push_str(&format!("{}: {},\n", expr.id, expr.id).to_string());
                }
            },
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
                            "\tdata.write_{}(self.{}[{}]).unwrap();\n",
                            &"u8".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}(self.{}).unwrap();\n",
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
                            "\tdata.write_{}::<BigEndian>(self.{}[{}]).unwrap();\n",
                            &"i8".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(self.{}).unwrap();\n",
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
                            "\tdata.write_{}::<BigEndian>(self.{}[{}]).unwrap();\n",
                            &"u16".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(self.{}).unwrap();\n",
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
                            "\tdata.write_{}::<BigEndian>(self.{}[{}]).unwrap();\n",
                            &"i16".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(self.{}).unwrap();\n",
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
                            "\tdata.write_{}::<BigEndian>(self.{}[{}]).unwrap();\n",
                            &"u32".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(self.{}).unwrap();\n",
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
                            "\tdata.write_{}::<BigEndian>(self.{}[{}]).unwrap();\n",
                            &"i32".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(self.{}).unwrap();\n",
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
                            "\tdata.write_{}::<BigEndian>(self.{}[{}]).unwrap();\n",
                            &"u64".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(self.{}).unwrap();\n",
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
                            "\tdata.write_{}::<BigEndian>(self.{}[{}]).unwrap();\n",
                            &"i64".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(self.{}).unwrap();\n",
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
                            "\tdata.write_{}::<BigEndian>(self.{}[{}]).unwrap();\n",
                            &"f32".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(self.{}).unwrap();\n",
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
                            "\tdata.write_{}::<BigEndian>(self.{}[{}]).unwrap();\n",
                            &"f64".to_string(),
                            expr.id,
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tdata.write_{}::<BigEndian>(self.{}).unwrap();\n",
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
                "LittleEndian::read_{}(&{}[{}..{}])",
                data_type,
                variable,
                position,
                position + data_byte_size
            )
        }
    }

    fn datatype_to_rust_type(data_type: String) -> String {
        match data_type.as_str() {
            "float64" => "f64",
            _ => "unknown",
        }
        .to_string()
    }
}
