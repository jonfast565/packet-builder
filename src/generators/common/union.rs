//! Pieces of tagged unions shared by the backends.

use super::naming::pascal_case;
use crate::ir::Arm;

/// How a language spells "or" and "not" in conditions.
pub struct Logic {
    pub or: &'static str,
    pub not: &'static str,
}

/// `||` and `!` (C, Rust, Go, C#).
pub const C_LOGIC: Logic = Logic { or: "||", not: "!" };
/// `or` and `not` (Python).
pub const PY_LOGIC: Logic = Logic { or: "or", not: "not " };
/// `or` and `!` (Zig).
pub const ZIG_LOGIC: Logic = Logic { or: "or", not: "!" };

/// The condition under which the selector held in `var` picks `arm`, or
/// None when every value does (a default arm and no other values).
pub fn arm_test(arm: &Arm, arms: &[Arm], var: &str, l: &Logic) -> Option<String> {
    let any = |vals: &[i64]| {
        vals.iter().map(|v| format!("{} == {}", var, v)).collect::<Vec<_>>().join(&format!(" {} ", l.or))
    };
    if arm.default {
        let others: Vec<i64> = arms.iter().filter(|a| !a.default).flat_map(|a| a.values.clone()).collect();
        if others.is_empty() { None } else { Some(format!("{}({})", l.not, any(&others))) }
    } else {
        Some(format!("({})", any(&arm.values)))
    }
}

/// True if some arm's test needs the selector (it is not all defaults).
pub fn uses_selector(arms: &[Arm]) -> bool {
    arms.iter().any(|a| !a.default)
}

/// The PascalCase name of an arm (`keep_alive` → `KeepAlive`).
pub fn variant_name(arm: &Arm) -> String {
    pascal_case(&arm.name)
}

/// The error message when a union holds an arm its selector does not pick.
pub fn mismatch_message(member: &str, arm: &Arm) -> String {
    format!("`{}` holds arm `{}`, but its selector picks another arm", member, arm.name)
}
