pub trait Casing {
    fn to_camel_case(&self) -> String;
    fn to_snake_case(&self) -> String;
    fn split_string_by(&self, char_func: fn(char) -> bool) -> Vec<String>;
}

impl Casing for String {
    fn to_camel_case(&self) -> String {
        if self.is_empty() || self.len() < 2 {
            self.clone()
        } else {
            let mut first = self.chars().nth(0).unwrap().to_lowercase().to_string();
            let second = self[1..].to_string();
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

        for c in self.chars() {
            if char_func(c) {
                result.push(intermediate_result.clone());
                intermediate_result.clear();
                intermediate_result.push(c);
            } else {
                intermediate_result.push(c)
            }
        }

        result.push(intermediate_result);
        result.remove(0);
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