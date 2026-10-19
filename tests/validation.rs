//! The analyzer must reject malformed packet descriptions with a useful,
//! located message instead of generating broken code.

use packet_builder::{CompileError, compile};

fn error_of(src: &str) -> String {
    match compile(src) {
        Ok(_) => panic!("expected an error for:\n{}", src),
        Err(e) => {
            // Rendering must not panic either.
            let _ = e.render("test.packet", src);
            e.to_string()
        }
    }
}

fn assert_error(src: &str, needle: &str) {
    let msg = error_of(src);
    assert!(msg.contains(needle), "expected error containing {:?}, got:\n{}", needle, msg);
}

#[test]
fn examples_compile() {
    for file in ["examples/oscar.packet", "examples/network.packet", "tests/specs/features.packet"] {
        let src = std::fs::read_to_string(file).unwrap();
        if let Err(e) = compile(&src) {
            panic!("{}:\n{}", file, e.render(file, &src));
        }
    }
}

#[test]
fn standard_types_must_be_byte_aligned() {
    assert_error("packet P { a u3, b uint16, _ u5 }", "uint16 `b` starts 3 bit(s) into a byte");
}

#[test]
fn bit_types_cannot_take_a_byte_order_when_unaligned() {
    assert_error("packet P { a u4, b u16 le, _ u4 }", "cannot have a byte order");
}

#[test]
fn packets_must_be_whole_bytes() {
    assert_error("packet P { a u3 }", "ends 3 bit(s) into a byte");
    assert_error("packet P { n uint8, a u3[n] }", "may not be a whole number of bytes");
}

#[test]
fn bit_arrays_with_byte_multiple_lengths_are_aligned() {
    assert!(compile("packet P { n uint8, a u12[n * 2], b uint8 }").is_ok());
    assert!(compile("packet P { n uint8, a u4[n * 2], b uint8 }").is_ok());
}

#[test]
fn bitfield_members_must_fit() {
    assert_error("packet P { f bitfield uint8 { a u4, b u5 } }", "members use 9 bits but the container has only 8");
}

#[test]
fn bitfield_container_must_be_an_integer() {
    assert_error("packet P { f bitfield float32 { a u4 } }", "needs an integer container");
    assert_error("packet P { f bitfield bytes { a u4 } }", "needs an integer container");
}

#[test]
fn bit_widths_are_limited_to_64() {
    assert_error("packet P { a u65 }", "between 1 and 64");
    assert_error("packet P { a u0, _ u8 }", "between 1 and 64");
}

#[test]
fn lengths_must_reference_known_fields() {
    assert_error("packet P { data bytes[len] }", "unknown field `len`");
}

#[test]
fn lengths_must_reference_earlier_fields() {
    assert_error("packet P { data bytes[len], len uint8 }", "uses `len`, which is not known yet");
}

#[test]
fn lengths_may_use_calculated_fields_of_earlier_data() {
    assert!(compile("packet P { n uint8, data bytes[size], calc size uint16 = n * 2 }").is_ok());
}

#[test]
fn rest_of_input_fields_must_be_last() {
    assert_error("packet P { data bytes, tail uint8 }", "must be the last field");
    assert_error("packet P { data uint16[], tail uint8 }", "must be the last field");
}

#[test]
fn open_ended_packets_must_be_nested_last() {
    assert_error("packet Inner { rest bytes[] } packet Outer { a Inner, b uint8 }", "consumes the rest of the input");
}

#[test]
fn unknown_types_are_reported() {
    assert_error("packet P { a Missing }", "unknown type `Missing`");
}

#[test]
fn recursive_packets_are_rejected() {
    assert_error("packet A { b B } packet B { a A }", "contains itself");
}

#[test]
fn duplicate_names_are_rejected() {
    assert_error("packet P { a uint8, a uint8 }", "declared more than once");
    assert_error("packet P { a uint8 } packet P { b uint8 }", "declared more than once");
    assert_error("packet P { f bitfield uint8 { a u4, _ u4 }, a uint8 }", "declared more than once");
}

#[test]
fn reserved_prefixes_are_rejected() {
    assert_error("packet P { pb_x uint8 }", "reserved");
}

#[test]
fn calculated_fields_cannot_depend_on_themselves() {
    assert_error("packet P { a uint8, calc x uint8 = y + 1, calc y uint8 = x }", "depends on itself");
}

#[test]
fn arrays_need_an_index_in_expressions() {
    assert_error("packet P { n uint8, v uint8[n], calc s uint8 = v + 1 }", "is an array");
    assert!(compile("packet P { n uint8, v uint8[n], calc s uint8 = v[0] + sumof v }").is_ok());
}

#[test]
fn non_numeric_values_cannot_be_used_in_expressions() {
    assert_error("packet P { m macaddress, calc x uint8 = m }", "mac address");
    assert_error("packet P { a uint8, calc x uint8 = \"s\" }", "string literals");
}

#[test]
fn function_arity_is_checked() {
    assert_error("packet P { a uint8, calc x uint8 = min(a) }", "exactly two arguments");
}

#[test]
fn comparisons_do_not_chain() {
    assert!(matches!(compile("packet P { a uint8, calc x uint8 = 1 < a < 3 }"), Err(CompileError::Parse(_))));
    assert!(compile("packet P { a uint8, calc x uint8 = a <> 3 }").is_ok());
}

#[test]
fn padding_must_be_an_integer() {
    assert_error("packet P { _ float32 }", "padding");
}

#[test]
fn nested_packets_must_be_aligned() {
    assert_error("packet I { a uint8 } packet P { x u4, i I, _ u4 }", "nested packets must be byte aligned");
}

#[test]
fn parse_errors_are_located() {
    let src = "packet P {\n  a uint8\n  b uint8\n}";
    let err = compile(src).unwrap_err();
    let rendered = err.render("test.packet", src);
    assert!(rendered.contains("test.packet:3"), "{}", rendered);
}
