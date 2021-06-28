use pest::error::Error;
use pest::Parser;

#[grammar = "../grammar.pest"]
#[derive(Parser)]
pub struct PacketParser2;

pub fn parse_file(input: &String) -> Result<String, Error<Rule>> {
    let packets = PacketParser2::parse(Rule::packets, input)?.next().unwrap();
    parse_packets(packets);
    Ok(String::new())
}

fn parse_packets(packets: pest::iterators::Pair<Rule>) {
    match packets.as_rule() {
        Rule::packets => {
            let packet_list = packets.into_inner();
            for packet in packet_list {
                parse_packet(packet)
            }
        }
        _ => (),
    }
}

fn parse_packet(packet: pest::iterators::Pair<Rule>) {
    match packet.as_rule() {
        Rule::packet => {
            let packet_details = packet.into_inner();
            let mut identifier = String::new();
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
                                                parse_calculated_field(rule_with_type);
                                            }
                                            Rule::declaration => {
                                                parse_packet_rule(rule_with_type);
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
}

fn parse_packet_rule(packet_rule: pest::iterators::Pair<Rule>) {
    dbg!("Packet field", packet_rule);
}

fn parse_calculated_field(packet_rule: pest::iterators::Pair<Rule>) {
    dbg!("Calculated field", packet_rule);
}
