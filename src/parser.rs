use pest::error::Error;
use pest::Parser;

#[grammar = "../grammar.pest"]
#[derive(Parser)]
pub struct PacketParser2;

pub fn parse_file(input: &String) -> Result<String, Error<Rule>> {
    let packet = PacketParser2::parse(Rule::Packets, input)?.next().unwrap();
    dbg!(packet);
    Ok(String::new())
}
