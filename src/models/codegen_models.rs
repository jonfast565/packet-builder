use crate::utilities::Casing;

pub struct VariableName {
    pub pascal_case_name: String,
    pub camel_case_name: String,
    pub snake_case_name: String
}

impl VariableName {
    pub fn from_string(name: &String) -> VariableName {
        VariableName {
            pascal_case_name: name.to_string(),
            camel_case_name: name.to_camel_case(),
            snake_case_name: name.to_snake_case()
        }
    }
}