use crate::models::parsing_models::{ExprNode, PacketExpr, TypeExpr};
use crate::utilities::{capitalize_first, CaseWrapper, Casing};

pub struct GoGenerator {}

impl GoGenerator {
    pub fn generate(expr: &Vec<PacketExpr>) -> String {
        let mut result = String::new();
        result.push_str(&GoGenerator::create_headers());
        result.push_str(&GoGenerator::create_spacer());
        result.push_str(&GoGenerator::create_supporting_functions());
        result.push_str(&GoGenerator::create_spacer());
        for exp in expr {
            result.push_str(&GoGenerator::build_struct(&exp, false));
            result.push_str(&GoGenerator::create_serialization_functions(&exp));
        }
        result
    }

    fn create_spacer() -> String {
        "\n".to_string()
    }

    fn create_headers() -> String {
        "\tpackage packets

        import ()
        "
        .to_string()
    }

    fn create_supporting_functions() -> String {
        "\t
        "
        .to_string()
    }

    fn create_serialization_functions(expr: &PacketExpr) -> String {
        format!(
            "\t/*func (*{}) Serialize() []byte {{
            var data = make([]byte, {})
            {}
            return data
        }}*/

        func Deserialize{}(data []byte) *{} {{
            var packet = new({})
            {}
            return packet
        }}

        ",
            expr.name,
            expr.get_total_length(),
            &GoGenerator::create_serializers(expr),
            expr.name,
            expr.name,
            expr.name,
            &GoGenerator::create_deserializers(expr)
        )
        .to_string()
    }

    fn build_struct(expr: &PacketExpr, just_fields: bool) -> String {
        let field_aggregation = expr
            .fields
            .iter()
            .map(|x| match x.expr {
                ExprNode::UnsignedInteger8(y) => {
                    format!("{} {}uint8", CaseWrapper(x.id.clone()).to_pascal_case(), GoGenerator::get_array_bounds(y))
                }
                ExprNode::Integer8(y) => {
                    format!("{} {}int8", CaseWrapper(x.id.clone()).to_pascal_case(), GoGenerator::get_array_bounds(y))
                }
                ExprNode::UnsignedInteger16(y) => {
                    format!("{} {}uint16", CaseWrapper(x.id.clone()).to_pascal_case(), GoGenerator::get_array_bounds(y))
                }
                ExprNode::Integer16(y) => {
                    format!("{} {}int16", CaseWrapper(x.id.clone()).to_pascal_case(), GoGenerator::get_array_bounds(y))
                }
                ExprNode::UnsignedInteger32(y) => {
                    format!("{} {}uint32", CaseWrapper(x.id.clone()).to_pascal_case(), GoGenerator::get_array_bounds(y))
                }
                ExprNode::Integer32(y) => {
                    format!("{} {}int32", CaseWrapper(x.id.clone()).to_pascal_case(), GoGenerator::get_array_bounds(y))
                }
                ExprNode::UnsignedInteger64(y) => {
                    format!("{} {}uint64", CaseWrapper(x.id.clone()).to_pascal_case(), GoGenerator::get_array_bounds(y))
                }
                ExprNode::Integer64(y) => {
                    format!("{} {}int64 ", CaseWrapper(x.id.clone()).to_pascal_case(), GoGenerator::get_array_bounds(y))
                }
                ExprNode::Float32(y) => {
                    format!("{} {}float32", CaseWrapper(x.id.clone()).to_pascal_case(), GoGenerator::get_array_bounds(y))
                }
                ExprNode::Float64(y) => {
                    format!("{} {}float64", CaseWrapper(x.id.clone()).to_pascal_case(), GoGenerator::get_array_bounds(y))
                }
                _ => "".to_string(),
            })
            .fold(String::new(), |acc, v| format!("{}\t    {}\n", acc, v));

        if !just_fields {
            format!(
                "\ttype {} struct {{\n {} \n\t}}\n\n",
                expr.name, field_aggregation
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
            result.push_str(&GoGenerator::get_field_deserializer(field, &mut counter));
        }
        result
    }

    fn create_serializers(expr: &PacketExpr) -> String {
        let mut result = String::new();
        let mut counter = 0;
        for field in &expr.fields {
            result.push_str(&GoGenerator::get_field_serializer(field, &mut counter));
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
                            "\tmemcpy(&(*data)[{}], packet.{}[{}], {});\n",
                            i,
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], packet.{}, {});\n",
                        *position,
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], packet.{}[{}], {});\n",
                            i,
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], packet.{}, {});\n",
                        *position,
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], packet.{}[{}], {});\n",
                            i,
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], packet.{}, {});\n",
                        *position,
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], packet.{}[{}], {});\n",
                            i,
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], packet.{}, {});\n",
                        *position,
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], packet.{}[{}], {});\n",
                            i,
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], packet.{}, {});\n",
                        *position,
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], packet.{}[{}], {});\n",
                            i,
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], packet.{}, {});\n",
                        *position,
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::UnsignedInteger64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], packet.{}[{}], {});\n",
                            i,
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], packet.{}, {});\n",
                        *position,
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Integer64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], packet.{}[{}], {});\n",
                            i,
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], packet.{}, {});\n",
                        *position,
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Float32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], packet.{}[{}], {});\n",
                            i,
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], packet.{}, {});\n",
                        *position,
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::Float64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&format!(
                            "\tmemcpy(&(*data)[{}], packet.{}[{}], {});\n",
                            i,
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            *position,
                            expr.expr.get_type_length_bytes()
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tmemcpy(&(*data)[{}], packet.{}, {});\n",
                        *position,
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        expr.expr.get_type_length_bytes()
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::MacAddress => {
                result.push_str(&format!("// Not implemented {}\n", &"data".to_string()));
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
                            "\tpacket.{}[{}] = {}\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            i,
                            GoGenerator::get_8bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = {}\n",
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        GoGenerator::get_8bit_conversion_deserialization(
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
                            "\tpacket.{}[{}] = {}\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            i,
                            GoGenerator::get_8bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = {}\n",
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        GoGenerator::get_8bit_conversion_deserialization(
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
                            "\tpacket.{}[{}] = {}\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            i,
                            GoGenerator::get_16bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = {}\n",
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        GoGenerator::get_16bit_conversion_deserialization(
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
                            "\tpacket.{}[{}] = {}\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            i,
                            GoGenerator::get_16bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = {}\n",
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        GoGenerator::get_16bit_conversion_deserialization(
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
                            "\tpacket.{}[{}] = {}\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            i,
                            GoGenerator::get_32bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = {}\n",
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        GoGenerator::get_32bit_conversion_deserialization(
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
                            "\tpacket.{}[{}] = {}\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            i,
                            GoGenerator::get_32bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = {}\n",
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        GoGenerator::get_32bit_conversion_deserialization(
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
                            "\tpacket.{}[{}] = {}\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            i,
                            GoGenerator::get_64bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = {}\n",
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        GoGenerator::get_64bit_conversion_deserialization(
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
                            "\tpacket.{}[{}] = {}\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            i,
                            GoGenerator::get_64bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = {}\n",
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        GoGenerator::get_64bit_conversion_deserialization(
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
                            "\tpacket.{}[{}] = {}\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            i,
                            GoGenerator::get_32bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = {}\n",
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        GoGenerator::get_32bit_conversion_deserialization(
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
                            "\tpacket.{}[{}] = {}\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            i,
                            GoGenerator::get_64bit_conversion_deserialization(
                                &"data".to_string(),
                                *position
                            )
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\tpacket.{} = {}\n",
                        CaseWrapper(expr.id.clone()).to_pascal_case(),
                        GoGenerator::get_64bit_conversion_deserialization(
                            &"data".to_string(),
                            *position
                        )
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            ExprNode::MacAddress => {
                result.push_str(&format!("// Not implemented {}\n", &"data".to_string()));
                *position += expr.expr.get_type_length_bytes();
            }
            _ => (),
        }
        result
    }

    fn get_8bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!("uint8({}[{}])", variable, position)
    }

    fn get_16bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!(
            "uint16({}[{}]) | 
                uint16({}[{}]) << 8",
            variable,
            position + 1,
            variable,
            position,
        )
    }

    fn get_32bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!(
            "uint32({}[{}]) |
                uint32({}[{}]) << 8 | 
                uint32({}[{}]) << 16 |
                uint32({}[{}]) << 24",
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
            "uint64({}[{}]) |
                uint64({}[{}]) << 8  | 
                uint64({}[{}]) << 16 |  
                uint64({}[{}]) << 24 |
                uint64({}[{}]) << 32 |
                uint64({}[{}]) << 40 |
                uint64({}[{}]) << 48 |
                uint64({}[{}]) << 56",
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
