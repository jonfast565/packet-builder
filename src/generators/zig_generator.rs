use crate::models::parsing_models::{ExprNode, PacketExpr, TypeExpr};

pub struct ZigGenerator {}

impl ZigGenerator {
    pub fn generate(expr: &Vec<PacketExpr>) -> String {
        let mut result = String::new();
        result.push_str(&ZigGenerator::create_headers());
        result.push_str(&ZigGenerator::create_spacer());
        result.push_str(&ZigGenerator::create_supporting_functions());
        result.push_str(&ZigGenerator::create_spacer());
        for exp in expr {
            result.push_str(&ZigGenerator::build_struct(&exp, false));
            result.push_str(&ZigGenerator::create_serialization_functions(&exp));
        }
        result
    }

    fn create_spacer() -> String {
        "\n".to_string()
    }

    fn create_headers() -> String {
        "\tconst std = @import(\"std\");
        const mem = @import(\"std\").mem;
        const allocator: *std.mem.Allocator = std.heap.page_allocator;
        "
        .to_string()
    }

    fn create_supporting_functions() -> String {
        "\tpub fn reverse(arr: []u8) []u8 {
            var low: u64 = 0;
            var high: u64 = arr.len - 1;
            while (low < high) {
                var temp: u64 = arr[low];
                arr[low] = arr[high];
                arr[high] = temp;
                low += 1;
                high -= 1;
            }
            return arr;
        }
        "
        .to_string()
    }

    fn create_serialization_functions(expr: &PacketExpr) -> String {
        format!(
            "\tpub fn serialize(packet: {}, verbose: bool) []u8 {{
            var data: []u8 = try allocator.alloc(u8, {});
            for (data[0..{}] |*v| v = 0;
            {}
        }}

        pub fn deserialize(data: []u8, verbose: bool) {} {{
            var packet: {} = allocator.alloc({}, 1);
            {}
        }}

        pub fn main() !void {{
            // std.io.stdout.print(\"-- Packet Tester --\");
        }}
        ",
            expr.name,
            expr.get_total_length(),
            expr.get_total_length(),
            &ZigGenerator::create_serializers(expr),
            expr.name,
            expr.name,
            expr.name,
            &ZigGenerator::create_deserializers(expr)
        )
        .to_string()
    }

    fn build_struct(expr: &PacketExpr, just_fields: bool) -> String {
        let field_aggregation = expr
            .fields
            .iter()
            .map(|x| match x.expr {
                ExprNode::UnsignedInteger8(y) => {
                    format!("{}: {}u8,", x.id, ZigGenerator::get_array_bounds(y))
                }
                ExprNode::Integer8(y) => {
                    format!("{}: {}i8,", x.id, ZigGenerator::get_array_bounds(y))
                }
                ExprNode::UnsignedInteger16(y) => {
                    format!("{}: {}u16,", x.id, ZigGenerator::get_array_bounds(y))
                }
                ExprNode::Integer16(y) => {
                    format!("{}: {}i16,", x.id, ZigGenerator::get_array_bounds(y))
                }
                ExprNode::UnsignedInteger32(y) => {
                    format!("{}: {}u32,", x.id, ZigGenerator::get_array_bounds(y))
                }
                ExprNode::Integer32(y) => {
                    format!("{}: {}i32,", x.id, ZigGenerator::get_array_bounds(y))
                }
                ExprNode::UnsignedInteger64(y) => {
                    format!("{}: {}u64,", x.id, ZigGenerator::get_array_bounds(y))
                }
                ExprNode::Integer64(y) => {
                    format!("{}: {}i64,", x.id, ZigGenerator::get_array_bounds(y))
                }
                ExprNode::Float32(y) => {
                    format!("{}: {}f32,", x.id, ZigGenerator::get_array_bounds(y))
                }
                ExprNode::Float64(y) => {
                    format!("{}: {}f64;", x.id, ZigGenerator::get_array_bounds(y))
                }
                _ => "".to_string(),
            })
            .fold(String::new(), |acc, v| format!("{}\t    {}\n", acc, v));

        if !just_fields {
            format!(
                "\tconst {} = struct {{\n {} \n\t}};\n\n",
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
            result.push_str(&ZigGenerator::get_field_deserializer(field, &mut counter));
        }
        result
    }

    fn create_serializers(expr: &PacketExpr) -> String {
        let mut result = String::new();
        let mut counter = 0;
        for field in &expr.fields {
            result.push_str(&ZigGenerator::get_field_serializer(field, &mut counter));
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
                            "\t{}[{}];\n",
                            &ZigGenerator::get_8bit_conversion_serialization(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                            ),
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &ZigGenerator::get_8bit_conversion_serialization(
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
                            "\t{}[{}];\n",
                            &ZigGenerator::get_8bit_conversion_serialization(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                            ),
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &ZigGenerator::get_8bit_conversion_serialization(
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
                            "\t{}[{}];\n",
                            &ZigGenerator::get_16bit_conversion_serialization(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                            ),
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &ZigGenerator::get_16bit_conversion_serialization(
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
                            "\t{}[{}];\n",
                            &ZigGenerator::get_16bit_conversion_serialization(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                            ),
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &ZigGenerator::get_16bit_conversion_serialization(
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
                            "\t{}[{}];\n",
                            &ZigGenerator::get_32bit_conversion_serialization(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                            ),
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &ZigGenerator::get_32bit_conversion_serialization(
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
                            "\t{}[{}];\n",
                            &ZigGenerator::get_32bit_conversion_serialization(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                            ),
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &ZigGenerator::get_32bit_conversion_serialization(
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
                            "\t{}[{}];\n",
                            &ZigGenerator::get_64bit_conversion_serialization(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                            ),
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &ZigGenerator::get_32bit_conversion_serialization(
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
                            "\t{}[{}];\n",
                            &ZigGenerator::get_64bit_conversion_serialization(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                            ),
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &ZigGenerator::get_64bit_conversion_serialization(
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
                            "\t{}[{}];\n",
                            &ZigGenerator::get_32bit_conversion_serialization(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                            ),
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &ZigGenerator::get_32bit_conversion_serialization(
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
                            "\t{}[{}];\n",
                            &ZigGenerator::get_64bit_conversion_serialization(
                                &"data".to_string(),
                                &expr.id,
                                *position,
                            ),
                            i
                        ));
                        *position += expr.expr.get_type_length_bytes();
                    }
                }
                None => {
                    result.push_str(&format!(
                        "\t{};\n",
                        &ZigGenerator::get_64bit_conversion_serialization(
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
                            ZigGenerator::get_8bit_conversion_deserialization(
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
                        ZigGenerator::get_8bit_conversion_deserialization(
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
                            ZigGenerator::get_8bit_conversion_deserialization(
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
                        ZigGenerator::get_8bit_conversion_deserialization(
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
                            ZigGenerator::get_16bit_conversion_deserialization(
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
                        ZigGenerator::get_16bit_conversion_deserialization(
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
                            ZigGenerator::get_16bit_conversion_deserialization(
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
                        ZigGenerator::get_16bit_conversion_deserialization(
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
                            ZigGenerator::get_32bit_conversion_deserialization(
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
                        ZigGenerator::get_32bit_conversion_deserialization(
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
                            ZigGenerator::get_32bit_conversion_deserialization(
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
                        ZigGenerator::get_32bit_conversion_deserialization(
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
                            ZigGenerator::get_64bit_conversion_deserialization(
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
                        ZigGenerator::get_64bit_conversion_deserialization(
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
                            ZigGenerator::get_64bit_conversion_deserialization(
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
                        ZigGenerator::get_64bit_conversion_deserialization(
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
                            ZigGenerator::get_32bit_conversion_deserialization(
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
                        ZigGenerator::get_32bit_conversion_deserialization(
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
                            ZigGenerator::get_64bit_conversion_deserialization(
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
                        ZigGenerator::get_64bit_conversion_deserialization(
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
            "{}[{}] = @intCast(u16, {});\n",
            result_variable, position, data_variable
        ) + &format!(
            "\t{}[{}] = @intCast(u16, {}) >> 8",
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
            "{}[{}] = @intCast(u32, {});\n",
            result_variable, position, data_variable
        ) + &format!(
            "\t{}[{}] = @intCast(u32, {}) >> 8;\n",
            result_variable,
            position + 1,
            data_variable
        ) + &format!(
            "\t{}[{}] = @intCast(u32, {}) >> 16;\n",
            result_variable,
            position + 2,
            data_variable
        ) + &format!(
            "\t{}[{}] = @intCast(u32, {}) >> 24",
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
            "{}[{}] = @intCast(u64, {});\n",
            result_variable, position, data_variable
        ) + &format!(
            "\t{}[{}] = @intCast(u64, {}) >> 8;\n",
            result_variable,
            position + 1,
            data_variable
        ) + &format!(
            "\t{}[{}] = @intCast(u64, {}) >> 16;\n",
            result_variable,
            position + 2,
            data_variable
        ) + &format!(
            "\t{}[{}] = @intCast(u64, {}) >> 24;\n",
            result_variable,
            position + 3,
            data_variable
        ) + &format!(
            "\t{}[{}] = @intCast(u64, {}) >> 32;\n",
            result_variable,
            position + 4,
            data_variable
        ) + &format!(
            "\t{}[{}] = @intCast(u64, {}) >> 40;\n",
            result_variable,
            position + 5,
            data_variable
        ) + &format!(
            "\t{}[{}] = @intCast(u64, {}) >> 48;\n",
            result_variable,
            position + 6,
            data_variable
        ) + &format!(
            "\t{}[{}] = @intCast(u64, {}) >> 56",
            result_variable,
            position + 7,
            data_variable
        )
    }

    fn get_8bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!("{}[{}]", variable, position)
    }

    fn get_16bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!(
            "@intCast(u16, {}[{}]) | 
                (@intCast(u16, {}[{}]) << 8)",
            variable,
            position + 1,
            variable,
            position,
        )
    }

    fn get_32bit_conversion_deserialization(variable: &String, position: usize) -> String {
        format!(
            "@intCast(u32, {}[{}]) |
                (@intCast(u32, {}[{}]) << 8) | 
                (@intCast(u32, {}[{}]) << 16) |
                (@intCast(u32, {}[{}]) << 24)",
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
            "@intCast(u64, {}[{}]) |
                (@intCast(u64, {}[{}]) << 8)  | 
                (@intCast(u64, {}[{}]) << 16) |  
                (@intCast(u64, {}[{}]) << 24) |
                (@intCast(u64, {}[{}]) << 32) |
                (@intCast(u64, {}[{}]) << 40) |
                (@intCast(u64, {}[{}]) << 48) |
                (@intCast(u64, {}[{}]) << 56)",
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
