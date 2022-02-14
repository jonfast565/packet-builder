use crate::models::parsing_models::{ExprNode, PacketExpr, TypeExpr, PacketExprList, TypeNode};
use crate::utilities::{capitalize_first, CaseWrapper, Casing};

pub struct CSharpGenerator {}

impl CSharpGenerator {
    pub fn generate(expr: &PacketExprList) -> String {
        let mut result = String::new();
        result.push_str(&CSharpGenerator::create_headers());
        result.push_str(&CSharpGenerator::create_spacer());
        result.push_str(&CSharpGenerator::create_spacer());
        for exp in &expr.packets {
            result.push_str(&CSharpGenerator::build_class(&exp, false));
        }
        result
    }

    fn create_spacer() -> String {
        "\n".to_string()
    }

    fn create_headers() -> String {
        "\t
        using System;
        using System.Buffers.Binary;
        "
        .to_string()
    }

    fn create_serialization_functions(expr: &PacketExpr) -> String {
        format!(
            "
        public byte[] Serialize() {{
            var data = new byte[{}] {{}};
            {}
            return data;
        }}

        public static {} Deserialize(byte[] data) {{
            {}
            var result = new {} {{
                {}
            }};
            return result;
        }}
        ",
            expr.get_total_length(),
            &CSharpGenerator::create_serializers(expr),
            expr.name,
            &CSharpGenerator::create_deserializers(expr),
            expr.name,
            &CSharpGenerator::create_deserializer_builders(expr)
        )
        .to_string()
    }

    fn build_class(expr: &PacketExpr, just_fields: bool) -> String {
        let field_aggregation = expr
            .fields
            .iter()
            .map(|x| match x.expr {
                TypeNode::UnsignedInteger8(y) => {
                    format!(
                        "public {} {} {{ get; set; }}",
                        CSharpGenerator::get_array_bounds("byte", y),
                        CaseWrapper(x.id.clone()).to_pascal_case()
                    )
                }
                TypeNode::Integer8(y) => {
                    format!(
                        "public {} {} {{ get; set; }}",
                        CSharpGenerator::get_array_bounds("sbyte", y),
                        CaseWrapper(x.id.clone()).to_pascal_case()
                    )
                }
                TypeNode::UnsignedInteger16(y) => {
                    format!(
                        "public {} {} {{ get; set; }}",
                        CSharpGenerator::get_array_bounds("ushort", y),
                        CaseWrapper(x.id.clone()).to_pascal_case()
                    )
                }
                TypeNode::Integer16(y) => {
                    format!(
                        "public {} {} {{ get; set; }}",
                        CSharpGenerator::get_array_bounds("short", y),
                        CaseWrapper(x.id.clone()).to_pascal_case()
                    )
                }
                TypeNode::UnsignedInteger32(y) => {
                    format!(
                        "public {} {} {{ get; set; }}",
                        CSharpGenerator::get_array_bounds("uint", y),
                        CaseWrapper(x.id.clone()).to_pascal_case()
                    )
                }
                TypeNode::Integer32(y) => {
                    format!(
                        "public {} {} {{ get; set; }}",
                        CSharpGenerator::get_array_bounds("int", y),
                        CaseWrapper(x.id.clone()).to_pascal_case()
                    )
                }
                TypeNode::UnsignedInteger64(y) => {
                    format!(
                        "public {} {} {{ get; set; }}",
                        CSharpGenerator::get_array_bounds("ulong", y),
                        CaseWrapper(x.id.clone()).to_pascal_case()
                    )
                }
                TypeNode::Integer64(y) => {
                    format!(
                        "public {} {} {{ get; set; }}",
                        CSharpGenerator::get_array_bounds("long", y),
                        CaseWrapper(x.id.clone()).to_pascal_case()
                    )
                }
                TypeNode::Float32(y) => {
                    format!(
                        "public {} {} {{ get; set; }}",
                        CSharpGenerator::get_array_bounds("float", y),
                        CaseWrapper(x.id.clone()).to_pascal_case()
                    )
                }
                TypeNode::Float64(y) => {
                    format!(
                        "public {} {} {{ get; set; }}",
                        CSharpGenerator::get_array_bounds("double", y),
                        CaseWrapper(x.id.clone()).to_pascal_case()
                    )
                }
                _ => "".to_string(),
            })
            .fold(String::new(), |acc, v| format!("{}\t    {}\n", acc, v));

        if !just_fields {
            format!(
                "public class {} {{\n {} \n \t{}}}\n\n",
                expr.name,
                field_aggregation,
                &CSharpGenerator::create_serialization_functions(&expr),
            )
        } else {
            format!("{}", field_aggregation)
        }
    }

    fn get_array_bounds(data_type: &str, expr: Option<usize>) -> String {
        match expr {
            Some(_x) => format!("{}[]", data_type),
            None => format!("{}", data_type.to_string()),
        }
    }

    fn create_deserializers(expr: &PacketExpr) -> String {
        let mut result = String::new();
        let mut counter = 0;
        for field in &expr.fields {
            result.push_str(&CSharpGenerator::get_field_deserializer(
                field,
                &mut counter,
            ));
        }
        result
    }

    fn create_deserializer_builders(expr: &PacketExpr) -> String {
        let mut result = String::new();
        for field in &expr.fields {
            result.push_str(&CSharpGenerator::get_field_serializer_builder(field));
        }
        result
    }

    fn get_field_serializer_builder(expr: &TypeExpr) -> String {
        let mut result = String::new();
        match expr.expr {
            TypeNode::UnsignedInteger8(y)
            | TypeNode::Integer8(y)
            | TypeNode::UnsignedInteger16(y)
            | TypeNode::Integer16(y)
            | TypeNode::UnsignedInteger32(y)
            | TypeNode::Integer32(y)
            | TypeNode::UnsignedInteger64(y)
            | TypeNode::Integer64(y)
            | TypeNode::Float32(y)
            | TypeNode::Float64(y) => match y {
                Some(y) => {
                    let mut array = String::new();
                    for i in 0..y {
                        array.push_str(
                            &format!("{}{}", CaseWrapper(expr.id.clone()).to_pascal_case(), i)
                                .to_string(),
                        );
                        if i < y - 1 {
                            array.push_str(", ");
                        }
                    }
                    result.push_str(
                        &format!(
                            "{} = new byte[] {{ {} }},\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            array
                        )
                        .to_string(),
                    );
                }
                None => {
                    result.push_str(
                        &format!(
                            "{} = {},\n",
                            CaseWrapper(expr.id.clone()).to_pascal_case(),
                            CaseWrapper(expr.id.clone()).to_pascal_case()
                        )
                        .to_string(),
                    );
                }
            },
            TypeNode::MacAddress => {}
            _ => (),
        };

        result
    }

    fn create_serializers(expr: &PacketExpr) -> String {
        let mut result = String::new();
        let mut counter = 0;
        for field in &expr.fields {
            result.push_str(&CSharpGenerator::get_field_serializer(field, &mut counter));
        }
        result
    }

    fn get_field_serializer(expr: &TypeExpr, position: &mut usize) -> String {
        let mut result = String::new();
        match expr.expr {
            TypeNode::UnsignedInteger8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_serialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"byte".to_string(),
                            1,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_serialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"byte".to_string(),
                        1,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_serialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"sbyte".to_string(),
                            1,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_serialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"sbyte".to_string(),
                        1,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_serialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"ushort".to_string(),
                            2,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_serialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"ushort".to_string(),
                        2,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_serialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"short".to_string(),
                            2,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_serialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"short".to_string(),
                        2,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_serialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"uint".to_string(),
                            4,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_serialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"uint".to_string(),
                        4,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_serialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"int".to_string(),
                            4,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_serialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"int".to_string(),
                        4,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_serialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"ulong".to_string(),
                            8,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_serialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"ulong".to_string(),
                        8,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_serialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"long".to_string(),
                            8,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_serialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"long".to_string(),
                        8,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Float32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_serialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"float".to_string(),
                            4,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_serialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"float".to_string(),
                        4,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Float64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_serialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"double".to_string(),
                            8,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_serialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"double".to_string(),
                        8,
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
                        result.push_str(&CSharpGenerator::format_array_deserialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"byte".to_string(),
                            1,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_deserialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"byte".to_string(),
                        1,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer8(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_deserialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"sbyte".to_string(),
                            1,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_deserialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"sbyte".to_string(),
                        1,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_deserialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"ushort".to_string(),
                            2,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_deserialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"ushort".to_string(),
                        2,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer16(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_deserialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"short".to_string(),
                            2,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_deserialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"short".to_string(),
                        2,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_deserialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"uint".to_string(),
                            4,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_deserialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"uint".to_string(),
                        4,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_deserialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"int".to_string(),
                            4,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_deserialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"int".to_string(),
                        4,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::UnsignedInteger64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_deserialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"ulong".to_string(),
                            8,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_deserialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"ulong".to_string(),
                        8,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Integer64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_deserialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"long".to_string(),
                            8,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_deserialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"long".to_string(),
                        8,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Float32(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_deserialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"float".to_string(),
                            4,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_deserialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"float".to_string(),
                        4,
                    ));
                    *position += expr.expr.get_type_length_bytes();
                }
            },
            TypeNode::Float64(y) => match y {
                Some(y) => {
                    for i in 0..y {
                        result.push_str(&CSharpGenerator::format_array_deserialization_variable(
                            expr,
                            i,
                            *position,
                            &"data".to_string(),
                            &"double".to_string(),
                            8,
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&CSharpGenerator::format_deserialization_variable(
                        expr,
                        *position,
                        &"data".to_string(),
                        &"double".to_string(),
                        8,
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

    fn format_deserialization_variable(
        expr: &TypeExpr,
        position: usize,
        data_variable: &String,
        variable_type: &String,
        variable_type_size: usize,
    ) -> String {
        format!(
            "\tvar {} = {};\n",
            CaseWrapper(expr.id.clone()).to_pascal_case(),
            CSharpGenerator::get_conversion_deserialization(
                data_variable,
                variable_type,
                position,
                variable_type_size
            )
        )
    }

    fn format_array_deserialization_variable(
        expr: &TypeExpr,
        i: usize,
        position: usize,
        data_variable: &String,
        variable_type: &String,
        variable_type_size: usize,
    ) -> String {
        format!(
            "\tvar {}{} = {};\n",
            CaseWrapper(expr.id.clone()).to_pascal_case(),
            i,
            CSharpGenerator::get_conversion_deserialization(
                data_variable,
                variable_type,
                position,
                variable_type_size
            )
        )
    }

    fn format_serialization_variable(
        expr: &TypeExpr,
        position: usize,
        data_variable: &String,
        variable_type: &String,
        variable_type_size: usize,
    ) -> String {
        format!(
            "\tvar {} = new byte[{}];\n\t{} = {};\n",
            CaseWrapper(expr.id.clone()).to_camel_case(),
            variable_type_size,
            CSharpGenerator::get_conversion_serialization(
                data_variable,
                variable_type,
                position,
                variable_type_size
            ),
            CaseWrapper(expr.id.clone()).to_camel_case()
        )
    }

    fn format_array_serialization_variable(
        expr: &TypeExpr,
        i: usize,
        position: usize,
        data_variable: &String,
        variable_type: &String,
        variable_type_size: usize,
    ) -> String {
        format!(
            "\tvar {}_{} = new byte[{}];\n\t{} = {};\n",
            CaseWrapper(expr.id.clone()).to_camel_case(),
            i,
            variable_type_size,
            CSharpGenerator::get_conversion_serialization(
                data_variable,
                variable_type,
                position,
                variable_type_size
            ),
            CaseWrapper(expr.id.clone()).to_camel_case()
        )
    }

    fn get_conversion_serialization(
        data_variable: &String,
        data_type: &String,
        position: usize,
        data_byte_size: usize,
    ) -> String {
        if data_type == "byte" {
            format!("{}[{}]", data_variable, position)
        } else {
            format!(
                "BinaryPrimitives.Write{}LittleEndian({}[{}..{}])",
                capitalize_first(data_type.clone()),
                data_variable,
                position,
                position + data_byte_size
            )
        }
    }

    fn get_conversion_deserialization(
        data_variable: &String,
        data_type: &String,
        position: usize,
        data_byte_size: usize,
    ) -> String {
        if data_type == "byte" {
            format!("{}[{}]", data_variable, position)
        } else {
            format!(
                "BinaryPrimitives.Read{}LittleEndian({}[{}..{}])",
                capitalize_first(data_type.clone()),
                data_variable,
                position,
                position + data_byte_size
            )
        }
    }
}
