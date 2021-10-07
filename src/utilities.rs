pub struct CaseWrapper(pub String);

pub trait Casing {
    fn to_camel_case(&self) -> String;
    fn to_snake_case(&self) -> String;
    fn to_pascal_case(&self) -> String;
    fn split_string_by(&self, char_func: fn(char) -> bool) -> Vec<String>;
}

impl Casing for CaseWrapper {
    fn to_pascal_case(&self) -> String {
        if self.0.is_empty() || self.0.len() < 2 {
            self.0.clone()
        } else {
            let mut results = String::new();
            let splitted = self.split_string_by(|c| c == '_');
            for c in splitted {
                let mut first = c.chars().nth(0).unwrap().to_uppercase().to_string();
                let second = c[1..].to_string();
                first.push_str(&second);
                results.push_str(&first);
            }
            results
        }
    }

    fn to_camel_case(&self) -> String {
        if self.0.is_empty() || self.0.len() < 2 {
            self.0.clone()
        } else {
            let mut first = self.0.chars().nth(0).unwrap().to_lowercase().to_string();
            let second = self.0[1..].to_string();
            first.push_str(&second);
            first
        }
    }

    fn to_snake_case(&self) -> String {
        let mut results = String::new();
        let splitted = self.split_string_by(|c| c.is_uppercase());
        for c in splitted {
            results.push_str(&(String::from(c) + "_"));
        }

        results.trim_end_matches("_").to_string()
    }

    fn split_string_by(&self, char_func: fn(char) -> bool) -> Vec<String> {
        let mut result = Vec::<String>::new();
        let mut intermediate_result = String::new();

        for c in self.0.chars() {
            if !char_func(c) {
                intermediate_result.push(c);
            } else {
                result.push(intermediate_result.clone());
                intermediate_result.clear();
            }
        }

        result.push(intermediate_result);
        result
    }
}

pub fn is_little_endian() -> bool {
    if cfg!(target_endian = "big") {
        false
    } else {
        true
    }
}