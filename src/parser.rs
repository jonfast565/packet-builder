use pest::error::Error;
use pest::Parser;

#[derive(Parser)]
#[grammar = "../grammar.pest"]
pub struct PacketParser2;

pub fn parse_file(input: &String) -> Result<String, Error<Rule>> {
    let packet = PacketParser2::parse(Rule::packet, input)?.next().unwrap();
    Ok(String::new())
}
