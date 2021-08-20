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

fn parse_packet_rule(parser_rule: pest::iterators::Pair<Rule>) -> TypeExpr {
    let declaration = parser_rule.into_inner();
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

fn parse_calculated_field(parser_rule: pest::iterators::Pair<Rule>) -> CalculatedField {
    let calc_field_declaration = parser_rule.into_inner();
    let mut identifier = String::new();
    let mut type_name = String::new();
    let mut option_expr: Option<ExprNode> = None;
    let mut guard_expression: Option<ExprNode> = None;
    for field in calc_field_declaration {
        match field.as_rule() {
            Rule::identifier => identifier = field.as_str().to_string(),
            Rule::type_name => type_name = field.as_str().to_string(),
            Rule::expr => option_expr = Some(parse_expr(field)),
            Rule::guard_clause => guard_expression = Some(parse_guard_expression(field)),
            _ => (),
        }
    }
    CalculatedField {
        name: identifier,
        data_type: type_name,
        expr: Box::new(option_expr.unwrap()),
        guard_expr: match guard_expression {
            Some(x) => Some(Box::new(x.clone())),
            None => None,
        },
    }
}

fn parse_expr(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let expr = parser_rule.into_inner();
    for field in expr.clone() {
        match field.as_rule() {
            Rule::bool_and_or_expr => return parse_boolean_and_or_expr(field),
            _ => return ExprNode::NoExpr,
        }
    }
    ExprNode::NoExpr
}

fn parse_boolean_and_or_expr(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let mut rules = Vec::<ExprNode>::new();
    let bool_and_or_expr = parser_rule.into_inner();
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

fn parse_boolean_comp_expr(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let mut rules = Vec::<ExprNode>::new();
    let boolean_comp_expr = parser_rule.into_inner();
    for field in boolean_comp_expr.clone() {
        match field.as_rule() {
            Rule::sum => rules.push(parse_sum_expr(field)),
            _ => (),
        }
    }

    for field in boolean_comp_expr.clone() {
        match field.as_rule() {
            Rule::greater_than => {
                return ExprNode::Gt(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            Rule::greater_than_equal => {
                return ExprNode::Gte(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            Rule::less_than => {
                return ExprNode::Lt(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
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

fn parse_sum_expr(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let mut rules = Vec::<ExprNode>::new();
    let sum_expr = parser_rule.into_inner();
    for field in sum_expr.clone() {
        match field.as_rule() {
            Rule::product => rules.push(parse_product_expr(field)),
            _ => (),
        }
    }

    for field in sum_expr.clone() {
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

fn parse_product_expr(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let mut rules = Vec::<ExprNode>::new();
    let product_expr = parser_rule.into_inner();
    for field in product_expr.clone() {
        match field.as_rule() {
            Rule::power => rules.push(parse_power_expr(field)),
            _ => (),
        }
    }

    for field in product_expr.clone() {
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

fn parse_power_expr(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let mut rules = Vec::<ExprNode>::new();
    let power_expr = parser_rule.into_inner();

    for field in power_expr.clone() {
        match field.as_rule() {
            Rule::value => rules.push(parse_value_expr(field)),
            _ => (),
        }
    }

    for field in power_expr.clone() {
        match field.as_rule() {
            Rule::pw => {
                return ExprNode::Pow(Box::new(rules[0].clone()), Box::new(rules[1].clone()))
            }
            _ => (),
        }
    }

    rules[0].clone()
}

fn parse_value_expr(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let value_expr = parser_rule.into_inner();
    for value in value_expr.clone() {
        match value.as_rule() {
            Rule::numeric_constant => {
                return parse_numeric_constant(value);
            }
            Rule::intrinsic_function_clause => return parse_intrinsic_function_clause(value),
            Rule::aggregate_accessor => {
                panic!("Not implemented yet")
            }
            Rule::direct_value_accessor => return parse_direct_value_accessor(value),
            Rule::inner_expr => {
                return ExprNode::ParenthesizedExpr(Box::new(parse_inner_expr(value)))
            }
            _ => (),
        }
    }

    ExprNode::NoExpr
}

fn parse_inner_expr(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let parenthesized_expr = parser_rule.into_inner();
    for value in parenthesized_expr.clone() {
        match value.as_rule() {
            Rule::expr => {
                return parse_expr(value);
            }
            _ => (),
        }
    }
    ExprNode::NoExpr
}

fn parse_numeric_constant(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let numeric_constant_value = parser_rule.as_str();
    if numeric_constant_value.to_string().contains(".") {
        return ExprNode::Float64Value(numeric_constant_value.parse::<f64>().unwrap());
    } else if numeric_constant_value.to_string().contains("-") {
        return ExprNode::Integer64Value(numeric_constant_value.parse::<i64>().unwrap());
    } else {
        return ExprNode::UnsignedInteger64Value(numeric_constant_value.parse::<u64>().unwrap());
    }
}

fn parse_direct_value_accessor(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let mut identifier = String::new();
    let mut array_specifier: Option<usize> = None;
    let direct_value_rule = parser_rule.into_inner();
    for value in direct_value_rule.clone() {
        match value.as_rule() {
            Rule::identifier => {
                identifier = value.as_str().to_string();
            }
            Rule::array_specifier => {
                let constant = value.into_inner();
                for c in constant {
                    match c.as_rule() {
                        Rule::numeric_constant => {
                            array_specifier = Some(c.as_str().parse::<usize>().unwrap());
                        }
                        _ => (),
                    }
                }
            }
            _ => (),
        }
    }
    ExprNode::ValueReference(identifier, array_specifier)
}

fn parse_intrinsic_function_clause(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let intrinsic_function_rule = parser_rule.into_inner();
    let mut function_name: String = String::new();
    let mut parameter_list = Vec::new();
    for value in intrinsic_function_rule.clone() {
        match value.as_rule() {
            Rule::intrinsic_function => {
                function_name = value.as_str().to_string();
            }
            Rule::parameter_list => {
                parameter_list = parse_parameter_list(value);
            }
            _ => (),
        }
    }
    ExprNode::ActivationRecord(function_name, parameter_list)
}

fn parse_parameter_list(parser_rule: pest::iterators::Pair<Rule>) -> Vec<ExprNode> {
    let parameter_list_rule = parser_rule.into_inner();
    let mut expression_list = Vec::new();
    for value in parameter_list_rule.clone() {
        match value.as_rule() {
            Rule::expr => {
                expression_list.push(parse_expr(value));
            }
            _ => {}
        }
    }
    expression_list
}

fn parse_guard_expression(parser_rule: pest::iterators::Pair<Rule>) -> ExprNode {
    let guard_clause_rule = parser_rule.into_inner();
    let mut exprs = Vec::new();
    for value in guard_clause_rule.clone() {
        match value.as_rule() {
            Rule::expr => exprs.push(parse_expr(value)),
            _ => (),
        }
    }
    ExprNode::GuardExpression(Box::new(exprs[0].clone()), Box::new(exprs[1].clone()))
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
