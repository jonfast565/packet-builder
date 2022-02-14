use crate::models::codegen_models::TwoStringValue;
use crate::models::parsing_models::{ExprNode, PacketExpr, PacketExprList, TypeExpr, TypeNode};
use crate::utilities::{capitalize_first, CaseWrapper, Casing};
use tera::{Context, Tera};

lazy_static! {
    pub static ref STATIC_TEMPLATES: Tera = {
        let tera = match Tera::new("templates/**/*") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };
        tera
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoPacketValue {
    pub name: String,
    pub endian: String,
    pub types: Vec<TwoStringValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoPacketRenderContext {
    pub packets: Vec<GoPacketValue>
}

pub struct GoGenerator {}

impl GoGenerator {
    pub fn generate(packet_list: &PacketExprList) -> String {
        let rendered = GoGenerator::expr_list_to_rendered(packet_list);
        match STATIC_TEMPLATES.render("go.tera", &Context::from_serialize(&rendered).unwrap()) {
            Ok(compiled) => return compiled,
            Err(err) => panic!("{}", err),
        };
    }

    pub fn expr_list_to_rendered(packet_list: &PacketExprList) -> GoPacketRenderContext {
        let mut value_vec = Vec::<GoPacketValue>::new();
        for packet in &packet_list.packets {
            value_vec.push(GoPacketValue {
                name: packet.name.clone(),
                endian: String::from("little"),
                types: GoGenerator::get_go_types(&packet)
            });
        }
        GoPacketRenderContext {
            packets: value_vec
        }
    }

    pub fn get_go_types(packet_expr: &PacketExpr) -> Vec<TwoStringValue> {
        let mut str_vec = Vec::<TwoStringValue>::new();
        for field in &packet_expr.fields {
            let result = match field.expr {
                TypeNode::UnsignedInteger8(y) => {
                    format!(
                        "{}{}",
                        match y {
                            Some(_) => "[]",
                            None => "",
                        },
                        "uint8"
                    )
                }
                TypeNode::Integer8(y) => {
                    format!(
                        "{}{}",
                        match y {
                            Some(_) => "[]",
                            None => "",
                        },
                        "int8"
                    )
                }
                TypeNode::UnsignedInteger16(y) => {
                    format!(
                        "{}{}",
                        match y {
                            Some(_) => "[]",
                            None => "",
                        },
                        "uint16"
                    )
                }
                TypeNode::Integer16(y) => {
                    format!(
                        "{}{}",
                        match y {
                            Some(_) => "[]",
                            None => "",
                        },
                        "int16"
                    )
                }
                TypeNode::UnsignedInteger32(y) => {
                    format!(
                        "{}{}",
                        match y {
                            Some(_) => "[]",
                            None => "",
                        },
                        "uint32"
                    )
                }
                TypeNode::Integer32(y) => {
                    format!(
                        "{}{}",
                        match y {
                            Some(_) => "[]",
                            None => "",
                        },
                        "int32"
                    )
                }
                TypeNode::UnsignedInteger64(y) => {
                    format!(
                        "{}{}",
                        match y {
                            Some(_) => "[]",
                            None => "",
                        },
                        "uint64"
                    )
                }
                TypeNode::Integer64(y) => {
                    format!(
                        "{}{}",
                        match y {
                            Some(_) => "[]",
                            None => "",
                        },
                        "int64"
                    )
                }
                TypeNode::Float32(y) => {
                    format!(
                        "{}{}",
                        match y {
                            Some(_) => "[]",
                            None => "",
                        },
                        "float32"
                    )
                }
                TypeNode::Float64(y) => {
                    format!(
                        "{}{}",
                        match y {
                            Some(_) => "[]",
                            None => "",
                        },
                        "float64"
                    )
                }
                _ => "".to_string(),
            };

            let name = capitalize_first(field.id.clone());
            let value = TwoStringValue { value1: name, value2: result };
            str_vec.push(value);
        }
        str_vec
    }
}
