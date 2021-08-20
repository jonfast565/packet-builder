use crate::models::parsing_models::{CalculatedField, ExprNode, PacketExpr, TypeExpr};
use pest::error::Error;
use pest::Parser;

#[derive(Parser)]
#[grammar = "../grammar.pest"]
pub struct PacketParser2;

pub fn parse_file(input: &String) -> Result<Vec<PacketExpr>, Error<Rule>> {
    let packets = PacketParser2::parse(Rule::packets, input)?.next().unwrap();
    let results = parse_packets(packets);
    Ok(results)
}

fn parse_packets(packets: pest::iterators::Pair<Rule>) -> Vec<PacketExpr> {
    let mut results = Vec::<PacketExpr>::new();
    match packets.as_rule() {
        Rule::packets => {
            let packet_list = packets.into_inner();
            for packet in packet_list {
                if packet.as_rule() == Rule::EOI {
                    continue;
                }
                results.push(parse_packet(packet));
            }
        }
        _ => (),
    }

    results
}

fn parse_packet(packet: pest::iterators::Pair<Rule>) -> PacketExpr {
    let mut type_rules = Vec::<TypeExpr>::new();
    let mut calculated_fields = Vec::<CalculatedField>::new();
    let mut identifier = String::new();
    match packet.as_rule() {
        Rule::packet => {
            let packet_details = packet.into_inner();
            for detail in packet_details {
                match detail.as_rule() {
                    Rule::identifier => identifier = detail.as_str().to_string(),
                    Rule::rule_list => {
                        let rules: Vec<pest::iterators::Pair<Rule>> = detail
                            .into_inner()
                            .filter(|x| x.as_rule() != Rule::listsep)
                            .collect();
                        for rule in rules {
                            match rule.as_rule() {
                                Rule::rule => {
                                    let rules_with_type = rule.into_inner();
                                    for rule_with_type in rules_with_type {
                                        match rule_with_type.as_rule() {
                                            Rule::calculated_field => {
                                                calculated_fields
                                                    .push(parse_calculated_field(rule_with_type));
                                            }
                                            Rule::declaration => {
                                                type_rules.push(parse_packet_rule(rule_with_type));
                                            }
                                            _ => (),
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
        _ => (),
    }

    PacketExpr {
        name: identifier,
        fields: type_rules,
        calculated_fields: calculated_fields,
    }
}

fn parse_packet_rule(packet_rule: pest::iterators::Pair<Rule>) -> TypeExpr {
    let declaration = packet_rule.into_inner();
    let mut identifier = String::new();
    let mut type_name = String::new();
    let mut array_length: Option<String> = None;

    for field in declaration {
        match field.as_rule() {
            Rule::identifier => identifier = field.as_str().to_string(),
            Rule::type_name => type_name = field.as_str().to_string(),
            Rule::array_specifier => {
                let array_number: Vec<pest::iterators::Pair<Rule>> = field
                    .into_inner()
                    .filter(|x| x.as_rule() == Rule::numeric_constant)
                    .collect();
                if array_number.len() > 0 {
                    array_length = Some(array_number[0].as_str().to_string());
                }
            }
            _ => (),
        }
    }

    TypeExpr {
        id: identifier,
        expr: expr_from_type_name(type_name, array_length),
    }
}

fn parse_calculated_field(packet_rule: pest::iterators::Pair<Rule>) -> CalculatedField {
    let calc_field_declaration = packet_rule.into_inner();
    let mut identifier = String::new();
    let mut type_name = String::new();
    let mut option_expr: Option<ExprNode> = None;
    for field in calc_field_declaration {
        match field.as_rule() {
            Rule::identifier => identifier = field.as_str().to_string(),
            Rule::type_name => type_name = field.as_str().to_string(),
            Rule::expr => option_expr = Some(parse_expr(field)),
            Rule::guard_clause => parse_guard_clause(field),
            _ => (),
        }
    }
    CalculatedField {
        name: identifier,
        type_name: type_name,
        expr: Box::new(option_expr.unwrap()),
    }
}

fn parse_expr(packet_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let bool_and_or_expr = packet_rule.into_inner();
    for field in bool_and_or_expr.clone() {
        match field.as_rule() {
            Rule::bool_and_or_expr => return parse_boolean_and_or_expr(field),
            _ => return ExprNode::NoExpr,
        }
    }
    ExprNode::NoExpr
}

fn parse_boolean_and_or_expr(packet_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let mut rules = Vec::<ExprNode>::new();
    let bool_and_or_expr = packet_rule.into_inner();
    for field in bool_and_or_expr.clone() {
        match field.as_rule() {
            Rule::bool_comp_expr => rules.push(parse_boolean_comp_expr(field)),
            _ => (),
        }
    }

    for field in bool_and_or_expr.clone() {
        match field.as_rule() {
            Rule::and_expr => {
                return ExprNode::And(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            Rule::or_expr => {
                return ExprNode::Or(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            _ => (),
        }
    }

    rules[0].clone()
}

fn parse_boolean_comp_expr(packet_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let mut rules = Vec::<ExprNode>::new();
    let bool_and_or_expr = packet_rule.into_inner();
    for field in bool_and_or_expr.clone() {
        match field.as_rule() {
            Rule::sum => rules.push(parse_sum_expr(field)),
            _ => (),
        }
    }

    for field in bool_and_or_expr.clone() {
        match field.as_rule() {
            Rule::greater_than => {
                return ExprNode::Gt(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            Rule::greater_than_equal => {
                return ExprNode::Gte(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            Rule::less_than => {
                return ExprNode::Gte(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            Rule::less_than_equal => {
                return ExprNode::Lte(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            Rule::equals => {
                return ExprNode::Equals(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            Rule::not_equals => {
                return ExprNode::NotEquals(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            _ => (),
        }
    }

    rules[0].clone()
}

fn parse_sum_expr(packet_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let mut rules = Vec::<ExprNode>::new();
    let bool_and_or_expr = packet_rule.into_inner();
    for field in bool_and_or_expr.clone() {
        match field.as_rule() {
            Rule::product => rules.push(parse_product_expr(field)),
            _ => (),
        }
    }

    for field in bool_and_or_expr.clone() {
        match field.as_rule() {
            Rule::plus => {
                return ExprNode::Plus(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            Rule::minus => {
                return ExprNode::Minus(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            _ => (),
        }
    }

    rules[0].clone()
}

fn parse_product_expr(packet_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let mut rules = Vec::<ExprNode>::new();
    let bool_and_or_expr = packet_rule.into_inner();
    for field in bool_and_or_expr.clone() {
        match field.as_rule() {
            Rule::power => rules.push(parse_power_expr(field)),
            _ => (),
        }
    }

    for field in bool_and_or_expr.clone() {
        match field.as_rule() {
            Rule::mult => {
                return ExprNode::Mult(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            Rule::div => {
                return ExprNode::Div(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            _ => (),
        }
    }

    rules[0].clone()
}

fn parse_power_expr(packet_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let mut rules = Vec::<ExprNode>::new();
    let bool_and_or_expr = packet_rule.into_inner();

    for field in bool_and_or_expr.clone() {
        match field.as_rule() {
            Rule::value => rules.push(parse_value_expr(field)),
            _ => (),
        }
    }

    rules[0].clone()
}

fn parse_value_expr(packet_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let value_expr = packet_rule.into_inner();

    for value in value_expr.clone() {
        match value.as_rule() {
            Rule::numeric_constant => {
                let constant = value.into_inner();
            }
            Rule::intrinsic_function_clause => {}
            Rule::aggregate_accessor => {}
            Rule::direct_value_accessor => {},
            Rule::inner_expr => {
                return ExprNode::ParenthesizedExpr(Box::new(parse_expr(value)))
            }
            _ => (),
        }
    }

    ExprNode::NoExpr
}

//fn parse_numeric_constant(packet_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    //
//}

fn parse_guard_clause(packet_rule: pest::iterators::Pair<Rule>) {
    // dbg!(packet_rule);
}

fn expr_from_type_name(type_name: String, array_length: Option<String>) -> ExprNode {
    match type_name.as_str() {
        "int8" => ExprNode::Integer8(match_array_length(array_length)),
        "uint8" => ExprNode::UnsignedInteger8(match_array_length(array_length)),
        "int16" => ExprNode::Integer16(match_array_length(array_length)),
        "uint16" => ExprNode::UnsignedInteger16(match_array_length(array_length)),
        "int32" => ExprNode::Integer32(match_array_length(array_length)),
        "uint32" => ExprNode::UnsignedInteger32(match_array_length(array_length)),
        "int64" => ExprNode::Integer64(match_array_length(array_length)),
        "uint64" => ExprNode::UnsignedInteger64(match_array_length(array_length)),
        "float32" => ExprNode::Float32(match_array_length(array_length)),
        "float64" => ExprNode::Float64(match_array_length(array_length)),
        _ => panic!("Not a type"),
    }
}

fn match_array_length(array_length: Option<String>) -> Option<usize> {
    match array_length {
        Some(x) => Some(x.as_str().parse::<usize>().unwrap()),
        None => None,
    }
}
