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
    for file in
        ["examples/oscar.packet", "examples/p3.packet", "examples/network.packet", "tests/specs/features.packet"]
    {
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

#[test]
fn type_aliases_follow_the_word_size() {
    let m = compile("packet P be { a half word, b word, c double word, d quad word }").unwrap();
    assert_eq!(m.packets[0].fixed_bits, Some(8 + 16 + 32 + 64));
    let m = compile("wordsize 32\npacket P be { a half word, b word, c double word }").unwrap();
    assert_eq!(m.packets[0].fixed_bits, Some(16 + 32 + 64));
}

#[test]
fn quad_words_need_16_bit_words() {
    assert_error("wordsize 32\npacket P { a qword }", "quad word would be 128 bits");
    assert_error("wordsize 24\npacket P { a word }", "wordsize must be 16 or 32");
}

#[test]
fn type_names_are_not_reserved_as_field_names() {
    assert!(compile("packet P { word uint16, string uint8, byte char, int int }").is_ok());
}

#[test]
fn packets_cannot_shadow_builtin_types() {
    assert_error("packet word { a uint8 }", "built-in type name");
    assert_error("packet u8 { a uint8 }", "built-in type name");
}

#[test]
fn strings_that_size_themselves_take_no_length() {
    assert_error("packet P { s cstring[4] }", "already determines its own length");
    assert_error("packet P { s string(uint8)[2] }", "already determines its own length");
}

#[test]
fn string_prefixes_must_be_unsigned_integers() {
    assert_error("packet P { s string(int8) }", "must be an unsigned integer type");
    assert!(compile("packet P { s string(u16 le) }").is_ok());
}

#[test]
fn strings_must_be_byte_aligned() {
    assert_error("packet P { a u4, s string[2], _ u4 }", "strings must be byte aligned");
    assert!(compile("packet P { a u4, align 1, s char[2] }").is_ok());
}

#[test]
fn strings_cannot_be_used_in_expressions() {
    assert_error("packet P { s char[4], calc n uint8 = s }", "is a string");
}

#[test]
fn rest_of_input_strings_must_be_last() {
    assert_error("packet P { s string, a uint8 }", "must be the last field");
}

#[test]
fn alignment_values_are_checked() {
    assert_error("packet P { a uint8 align 0 }", "between 1 and 4096");
    assert_error("packet P align 8192 { a uint8 }", "between 1 and 4096");
    assert_error("packet P { rest bytes, align 4 }", "follows a field that consumes the rest of the input");
}

#[test]
fn c_struct_layout_is_computed() {
    let m = compile("packet S le align 8 { a uint8, b uint32, c uint16, d uint64, e uint8 }").unwrap();
    assert_eq!(m.packets[0].fixed_bits, Some(32 * 8));
    assert_eq!(m.packets[0].alignment, 8);
    let m = compile("packet S le align 2 { a uint8, b uint32, c uint8 }").unwrap();
    assert_eq!(m.packets[0].fixed_bits, Some(8 * 8));
    // Without `align`, nothing is padded.
    let m = compile("packet S le { a uint8, b uint32, c uint8 }").unwrap();
    assert_eq!(m.packets[0].fixed_bits, Some(6 * 8));
}

#[test]
fn constants_are_resolved_in_expressions() {
    let m = compile(
        "const A uint8 = 0x10 \"note\"\nconst B uint16 = A * 2\nconst K u3 { x = 1, y = 2 }\n\
         packet P { n uint8 : K, data bytes[n - A + K.y] }",
    )
    .unwrap();
    assert_eq!(m.constants.len(), 2);
    assert_eq!(m.constants[1].value, 32);
    assert_eq!(m.constants[0].literal(), "0x10");
    assert_eq!(m.constants[0].note.as_deref(), Some("note"));
    assert_eq!(m.categories[0].members[1].value, 2);
    assert_eq!(m.packets[0].members[0].category.as_deref(), Some("K"));
}

#[test]
fn constant_values_are_checked() {
    assert_error("const A uint8 = 256\npacket P { a uint8 }", "the value 256 of `A` does not fit its type u8");
    assert_error("const A i4 = 8\npacket P { a uint8 }", "does not fit its type i4");
    assert_error("const A uint8 = sqrt(4)\npacket P { a uint8 }", "must be a constant integer expression");
    assert_error("const A uint8 = B\nconst B uint8 = 1\npacket P { a uint8 }", "unknown constant `B`");
    assert_error("const A float64 = 1\npacket P { a uint8 }", "must have an integer type");
    assert_error("const A bytes = 1\npacket P { a uint8 }", "must have an integer type");
}

#[test]
fn constant_names_are_checked() {
    assert_error(
        "const K uint8 { a = 1, a = 2 }\npacket P { x uint8 }",
        "`a` is declared more than once in category `K`",
    );
    assert_error("const K uint8 { keep_alive = 1, KeepAlive = 2 }\npacket P { x uint8 }", "declared more than once");
    assert_error("const P uint8 = 1\npacket P { x uint8 }", "constant `P` clashes with packet `P`");
    assert_error("const K uint8 { a = 1 }\nconst K_A uint8 = 2\npacket P { x uint8 }", "clashes with `K.a`");
    assert_error("const K uint8 { k = 1 }\npacket P { x uint8 }", "same name as its category");
    assert_error("const Constants uint8 { a = 1 }\npacket P { x uint8 }", "reserved by generated code");
    assert_error("const PB_X uint8 = 1\npacket P { x uint8 }", "reserved by generated code");
    assert_error("const x uint8 = 1\npacket P { x uint8 }", "same name as a constant");
    assert_error("const kind uint8 { a = 1 }\npacket P { x uint8 }", "must start with an uppercase letter");
    for name in ["EOF", "NULL", "INT8_MAX", "UINT64_C", "INTMAX_MAX", "UINT_LEAST8_MAX", "Math", "Array", "ValueError"]
    {
        assert_error(&format!("const {} uint8 = 1\npacket P {{ x uint8 }}", name), "reserved by generated code");
    }
    // Close to a reserved name is fine.
    compile("const EOF_MARKER uint8 = 1\nconst INT8 uint8 = 2\npacket P { x uint8 }").unwrap();
}

#[test]
fn constant_references_are_checked() {
    assert_error("const K uint8 { a = 1 }\npacket P { x uint8, calc c uint8 = K.b }", "has no constant `b` (it has a)");
    assert_error("packet P { x uint8, calc c uint8 = K.b }", "unknown category `K`");
    assert_error("const K uint8 { a = 1 }\npacket P { x uint8, calc c uint8 = K }", "is a category of constants");
}

#[test]
fn category_tags_are_checked() {
    assert_error("packet P { x uint8 : K }", "unknown category `K`");
    assert_error("const K uint8 = 1\npacket P { x uint8 : K }", "unknown category `K`");
    assert_error("const K uint8 { a = 1 }\npacket P { x float32 : K }", "`x` is not an integer");
    assert_error(
        "const K uint8 { a = 1, b = 9 }\npacket P { f bitfield uint8 { x u3 : K, _ u5 } }",
        "`K.b` = 9 does not fit `x` (u3)",
    );
    assert_error("const K int8 { a = 0 - 1 }\npacket P { x uint8 : K }", "`K.a` = -1 does not fit `x` (u8)");
}
