use crate::utilities::{Casing, CaseWrapper};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableName {
    pub pascal_case_name: String,
    pub camel_case_name: String,
    pub snake_case_name: String
}

impl VariableName {
    pub fn from_string(name: &String) -> VariableName {
        VariableName {
            pascal_case_name: name.to_string(),
            camel_case_name: CaseWrapper(name.to_string()).to_camel_case(),
            snake_case_name: CaseWrapper(name.to_string()).to_snake_case()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringValue {
    pub value: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoStringValue {
    pub value1: String,
    pub value2: String
}