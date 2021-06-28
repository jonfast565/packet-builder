use crate::utilities::Casing;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PacketParser {
    pub packet_groups: Vec<PacketGroup>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PacketGroup {
    pub name: String,
    pub packet_definition: Vec<PacketDefinition>,
    pub packet_multiplexer: PacketMultiplexer,
}

impl PacketGroup {
    pub fn post_process(&mut self) {
        let mut byte_counter = 0;
        for p in &mut self.packet_definition {
            let sequence_copy = p.sequence.clone();
            p.sequence.clear();
            for s in sequence_copy {
                let type_size = s.field_type.get_size();
                if s.repeat > 1 {
                    for i in 0..(s.repeat) {
                        let new_def = FieldDefinition {
                            length: type_size,
                            name: format!("{}{}", s.name, i).to_string(),
                            repeat: 1,
                            start_byte: byte_counter,
                            field_type: s.field_type.clone(),
                            variable_name: format!("{}{}", s.name.to_camel_case(), i).to_string(),
                        };
                        byte_counter += type_size;
                        p.sequence.push(new_def);
                    }
                } else {
                    let new_def = FieldDefinition {
                        length: type_size,
                        name: s.name.clone(),
                        repeat: 1,
                        start_byte: byte_counter,
                        field_type: s.field_type.clone(),
                        variable_name: format!("{}", s.name.to_camel_case()).to_string(),
                    };
                    byte_counter += type_size;
                    p.sequence.push(new_def);
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PacketDefinition {
    pub packet_name: String,
    pub sequence: Vec<FieldDefinition>,
    pub calculated_fields: Vec<CalculatedFields>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PacketMultiplexer {
    pub name: String,
    pub header_packet_definition: String,
    pub discriminator_begin: u32,
    pub discriminator_length: u32,
    pub choices: Vec<PacketMultiplexerChoice>,
}

impl PacketMultiplexer {
    pub fn get_discriminator_end(&self) -> u32 {
        self.discriminator_begin + self.discriminator_length
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PacketMultiplexerChoice {
    pub value: String,
    pub packet: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FieldDefinition {
    pub name: String,
    pub field_type: PacketFieldType,
    #[serde(default)]
    pub start_byte: u32,
    #[serde(default)]
    pub repeat: u32,
    #[serde(default)]
    pub length: u32,
    #[serde(default)]
    pub variable_name: String,
}

impl FieldDefinition {
    pub fn get_end_byte(&self) -> u32 {
        self.start_byte + self.field_type.get_size()
    }
    pub fn is_integer_8(&self) -> bool {
        self.field_type == PacketFieldType::Integer8
    }
    pub fn is_unsigned_integer_8(&self) -> bool {
        self.field_type == PacketFieldType::UnsignedInteger8
    }
    pub fn is_integer_16(&self) -> bool {
        self.field_type == PacketFieldType::Integer16
    }
    pub fn is_unsigned_integer_16(&self) -> bool {
        self.field_type == PacketFieldType::UnsignedInteger16
    }
    pub fn is_integer_32(&self) -> bool {
        self.field_type == PacketFieldType::Integer32
    }
    pub fn is_unsigned_integer_32(&self) -> bool {
        self.field_type == PacketFieldType::UnsignedInteger32
    }
    pub fn is_integer_64(&self) -> bool {
        self.field_type == PacketFieldType::Integer64
    }
    pub fn is_unsigned_integer_64(&self) -> bool {
        self.field_type == PacketFieldType::UnsignedInteger64
    }
    pub fn is_float_16(&self) -> bool {
        self.field_type == PacketFieldType::Float16
    }
    pub fn is_float_32(&self) -> bool {
        self.field_type == PacketFieldType::Float32
    }
    pub fn is_float_64(&self) -> bool {
        self.field_type == PacketFieldType::Float64
    }
    pub fn is_mac_address(&self) -> bool {
        self.field_type == PacketFieldType::MacAddress
    }
    pub fn is_date_time(&self) -> bool {
        self.field_type == PacketFieldType::DateTime
    }
    pub fn is_boolean(&self) -> bool {
        self.field_type == PacketFieldType::Boolean
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CalculatedFields {}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum PacketFieldType {
    Integer8,
    UnsignedInteger8,
    Integer16,
    UnsignedInteger16,
    Integer32,
    UnsignedInteger32,
    Integer64,
    UnsignedInteger64,
    Float16,
    Float32,
    Float64,
    MacAddress,
    DateTime,
    Boolean,
}

impl PacketFieldType {
    pub fn get_size(&self) -> u32 {
        match self {
            PacketFieldType::Integer8 => 1,
            PacketFieldType::UnsignedInteger8 => 1,
            PacketFieldType::Integer16 => 2,
            PacketFieldType::UnsignedInteger16 => 2,
            PacketFieldType::Integer32 => 4,
            PacketFieldType::UnsignedInteger32 => 4,
            PacketFieldType::Integer64 => 8,
            PacketFieldType::UnsignedInteger64 => 8,
            PacketFieldType::Float16 => 4,
            PacketFieldType::Float32 => 4,
            PacketFieldType::Float64 => 8,
            PacketFieldType::MacAddress => 6,
            PacketFieldType::DateTime => 4,
            PacketFieldType::Boolean => 1,
        }
    }
}
