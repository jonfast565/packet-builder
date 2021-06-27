use pest::Parser;

#[derive(Parser)]
#[grammar = "../grammar.pest"]
struct PacketParser;

impl PacketParser {
    fn parse(input: &String) {

    }
}