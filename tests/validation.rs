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
        if let Err(e) = packet_builder::compile_file(std::path::Path::new(file)) {
            panic!("{}:\n{}", file, e.render());
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
fn placeholders_are_constants_that_fit() {
    assert!(compile("packet P be { c uint16 = crc16_arc(d) placeholder 0x2a2a, d bytes[4] }").is_ok());
    assert_error("packet P be { n uint8, c uint8 = len(d) placeholder n, d bytes[] }", "constant integer");
    assert_error("packet P be { c uint8 = len(d) placeholder 256, d bytes[] }", "does not fit");
    assert_error("packet P be { c int8 = len(d) placeholder -129, d bytes[] }", "does not fit");
}

#[test]
fn remaining_is_only_for_calculated_fields() {
    assert_error("packet P { a uint8[remaining] }", "only be used in a calculated field");
    assert_error("packet P { n uint8, assert remaining > n }", "only be used in a calculated field");
    assert!(compile("packet P { calc n uint16 = remaining, data bytes[n] }").is_ok());
    // A field named `remaining` is just a field.
    assert!(compile("packet P { remaining uint8, data bytes[remaining] }").is_ok());
}

#[test]
fn remaining_calcs_use_only_earlier_fields() {
    assert_error("packet P { calc w uint8 = remaining - n, n uint8, d bytes[w] }", "not known yet");
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

#[test]
fn checks_need_single_integers() {
    assert_error("packet P { a uint8[2] == 1 }", "`a` is not a single integer");
    assert_error("packet P { s cstring == 1 }", "`s` is not a single integer");
}

#[test]
fn checked_values_are_constants_that_fit() {
    assert_error("packet P { a uint8, b uint8 == a }", "must be a constant integer expression");
    assert_error("packet P { a uint8 == 300 }", "300 does not fit `a`");
    assert_error("packet P { a u3 in 0..9 }", "9 does not fit `a`");
    assert_error("packet P { a uint8 in 5..1 }", "the range 5..1 of `a` is empty");
}

#[test]
fn strict_needs_a_category() {
    assert_error("const K uint8 { x = 1 }\npacket P { a uint8 : K, b uint8 strict }", "expected");
    assert_error("packet P { a uint8 : Missing strict }", "unknown category `Missing`");
}

#[test]
fn lenient_needs_a_check() {
    assert_error("packet P { a uint8 lenient }", "`lenient` on `a` has no check to relax");
}

#[test]
fn padding_cannot_be_checked() {
    assert_error("packet P { _ uint8 == 0 }", "padding (`_`) cannot have checks");
}

#[test]
fn assertions_are_type_checked() {
    assert_error("packet P { a uint8, assert b > 1 }", "unknown field `b`");
    assert_error("packet P { assert uint8 }", "unknown field `uint8`");
}

#[test]
fn checks_compile() {
    compile(
        "const K u4 { x = 1 }\npacket P be { a uint8 == 1, b u4 : K strict, c u4 in 0..3 lenient, assert a + c < 9 }",
    )
    .unwrap();
}

#[test]
fn wire_functions_only_derive_fields() {
    assert_error("packet P { a uint8, calc x uint8 = sizeof(a) }", "can only be used to derive a field");
    assert_error("packet P { a uint8, b uint8[crc8(a)] }", "can only be used to derive a field");
    assert_error("packet P { a uint8 = foo(a) }", "unknown function `foo`");
}

#[test]
fn derived_fields_are_single_integers() {
    assert_error("packet P { a uint8[2] = 1 }", "derived field `a` must be a single integer");
    assert_error("packet P { a float32 = 1 }", "derived field `a` must be a single integer");
    assert_error("packet P { _ uint8 = 1 }", "padding (`_`) cannot be derived");
}

#[test]
fn derived_fields_need_sensible_inputs() {
    assert_error("packet P { a uint8, b uint8 = len(a) }", "`a` is not an array or a string");
    assert_error("packet P { a uint8 = a + 1 }", "uses its own value");
    assert_error("packet P { a uint8, b uint8, c uint8 = sizeof(b..a) }", "comes after");
    assert_error("packet P { a uint8 = crc8(b), b uint8 = crc8(a) }", "depends on a field that depends on it");
    assert_error("packet P { f bitfield uint8 { x u4, y u4 }, s uint8 = sizeof(x) }", "not a field on the wire");
}

#[test]
fn measured_ranges_are_whole_bytes() {
    assert_error("packet P { a u4, s u4 = sizeof(a) }", "does not start and end on byte boundaries");
}

#[test]
fn derived_fields_compile() {
    compile(
        "packet P be { n uint8 = len(xs), xs uint16[n], s uint16 = sizeof(self) lenient, c uint32 = crc32(n..xs) }",
    )
    .unwrap();
}

#[test]
fn union_arms_are_distinct() {
    assert_error("packet P { t uint8, b switch t { 1 => a uint8, 1 => c uint8 } }", "value 1 selects both `a` and `c`");
    assert_error("packet P { t uint8, b switch t { _ => a uint8, _ => c uint8 } }", "has two `_` arms");
    assert_error("packet P { t uint8, b switch t { 1 => a uint8, 2 => a uint16 } }", "has two arms named `a`");
    assert_error("packet P { t uint8, b switch t { t => a uint8 } }", "must be constant integers");
}

#[test]
fn union_arms_hold_simple_types() {
    assert_error(
        "packet P { t uint8, b switch t { 1 => s cstring } }",
        "must hold a packet, an integer, bytes, or nothing",
    );
    assert_error(
        "packet P { t uint8, b switch t { 1 => s uint16[2] } }",
        "must hold a packet, an integer, bytes, or nothing",
    );
    assert_error("packet P { t uint8, b switch t { 1 => s Missing } }", "unknown type `Missing`");
}

#[test]
fn open_ended_unions_come_last() {
    assert_error("packet P { t uint8, b switch t { _ => r bytes[] }, x uint8 }", "must be the last field");
    compile("packet P { t uint8, n uint8, b switch t { _ => r bytes[] } size n, x uint8 }").unwrap();
}

#[test]
fn unions_are_not_values() {
    assert_error("packet P { t uint8, b switch t { _ => r uint8 }, calc x uint8 = b }", "`b` is a union");
}

#[test]
fn windows_start_on_bytes() {
    assert_error("packet P { a u4, b uint8 size 1, _ u4 }", "`b` has a size, so it must start on a byte boundary");
    assert_error("packet P { b uint8 size n, n uint8 }", "not known yet");
}

#[test]
fn union_type_names_are_free() {
    assert_error("packet PBody { }\npacket P { t uint8, body switch t { _ => x } }", "the union type `PBody`");
}

#[test]
fn padding_cannot_repeat_until_or_end_at_a_terminator() {
    assert_error("packet P { _ uint8[] until last == 0 }", "padding (`_`) cannot use `until` or `term`");
}

#[test]
fn until_and_term_are_exclusive() {
    assert_error("packet P { a uint8[] until last == 0 term 0x00 }", "`a` cannot have both `until` and `term`");
}

#[test]
fn until_needs_an_open_array() {
    assert_error("packet P { a uint8[2] until last == 0 }", "`until` on `a` needs an array without a length");
    assert_error("packet P { a uint8 until a == 0 }", "`until` on `a` needs an array without a length");
}

#[test]
fn term_applies_to_open_bytes_and_strings() {
    assert_error("packet P { a uint16[] term 0x00 }", "`term` on `a` applies to bytes and strings without a length");
    assert_error("packet P { a bytes[4] term 0x00 }", "`term` on `a` applies to bytes and strings without a length");
}

#[test]
fn terminators_are_bytes() {
    assert_error("packet P { a bytes term 0x100 }", "terminator byte 256 of `a` is not a byte");
}

#[test]
fn text_encodings_apply_to_strings() {
    assert_error("packet P { a uint8 latin1 }", "`a` is not a string, so it cannot have the text encoding `latin1`");
    assert_error("packet P { a cstring utf16le }", "`a` is UTF-16, so it cannot end at a byte terminator");
    assert_error("packet P { a string term 0x00 utf16be }", "`a` is UTF-16, so it cannot end at a byte terminator");
}

#[test]
fn last_names_a_field_of_a_packet_element() {
    assert_error(
        "packet E { k uint8 } packet P { a E[] until last == 0 }",
        "`last` is a `E`; name one of its fields, as in `last.kind`",
    );
    assert_error("packet P { a uint8[] until last.k == 0 }", "`last` is not a packet, so it has no fields");
}

#[test]
fn varints_are_byte_aligned_without_a_byte_order() {
    assert_error("packet P { a u3, b uleb128, _ u5 }", "variable-length integers");
    assert_error("packet P { a uleb128 le }", "varint `a` cannot have a byte order");
}

#[test]
fn varints_cannot_be_patched() {
    assert_error(
        "packet P { n uleb128 = sizeof(data), data bytes[n] }",
        "varint `n` cannot be derived from the encoded bytes",
    );
}

#[test]
fn parameters_are_integers() {
    assert_error("packet B(x float32) { a uint8 }", "parameter `x` of `B` must have an integer type");
}

#[test]
fn parameters_and_fields_have_different_names() {
    assert_error("packet B(a uint8) { a uint8 }", "`a` is both a parameter and a field of packet `B`");
}

#[test]
fn arguments_match_the_parameters() {
    assert_error(
        "packet B(n uint8) { a uint8[n] } packet P { b B }",
        "packet `B` takes 1 argument(s), but `b` passes 0",
    );
    assert_error("packet B { a uint8 } packet P { b B(1) }", "packet `B` takes 0 argument(s), but `b` passes 1");
}

#[test]
fn arguments_use_known_values() {
    assert_error(
        "packet B(n uint8) { a uint8[n] } packet P { b B(n), n uint8 }",
        "the arguments of `b` uses `n`, which is not known yet",
    );
}

#[test]
fn at_fields_are_single_packets() {
    assert_error("packet P { o uint8, a uint16 at o }", "`a` uses `at`, so it must be a single packet");
    assert_error(
        "packet E { a uint8 } packet P { o uint8, e E[2] at o }",
        "`e` uses `at`, so it cannot also have a length, `until`, `size`, `align` or `=`",
    );
    assert_error(
        "packet E { a uint8 } packet P { e E at o, o uint8 }",
        "the offset of `e` uses `o`, which is not known yet",
    );
}

#[test]
fn recursion_needs_an_array_or_at() {
    assert_error("packet A { b B } packet B { a A }", "contains itself");
    assert_error("packet A { x uint8, a A }", "packet `A` contains itself");
    // Through an array or `at`, it is fine.
    compile("packet A { n uint8, kids A[n] }").expect("array recursion");
    compile("packet A { o uint8, next A at root o }").expect("at recursion");
    compile("packet A { b B } packet B { n uint8, a A[n] }").expect("mutual recursion");
}

#[test]
fn dissector_declarations_are_checked() {
    assert_error("packet P { a uint8 } dissector Q { }", "dissector for unknown packet `Q`");
    assert_error("packet P { a uint8 } dissector P { abbrev \"Bad Name\" }", "is not a protocol abbreviation");
    assert_error("packet P { a uint8 } dissector P { colour \"red\" }", "unknown dissector option `colour`");
    assert_error(
        "packet P(n uint8) { a uint8 } dissector P { }",
        "packet `P` takes parameters, so it cannot have a dissector of its own",
    );
    assert_error(
        "packet P { a uint8 } packet Q { b uint8 } dissector P { abbrev \"x\" } dissector Q { abbrev \"x\" }",
        "two dissectors are called `x`",
    );
    let m = compile("packet P { a uint8 } dissector P { name \"Pee\", udp.port 4000, heuristic }").unwrap();
    assert_eq!(m.dissectors[0].abbrev, "p");
    assert_eq!(m.dissectors[0].tables, [("udp.port".to_string(), 4000)]);
    assert!(m.dissectors[0].heuristic);
}

#[test]
fn version_ranges_need_a_version_declaration() {
    assert_error("packet P { @2 a uint8 }", "need a `version N` declaration");
    assert_error("packet P { a uint8 = 1, @2 a = 2 }", "need a `version N` declaration");
}

#[test]
fn version_ranges_stay_within_the_versions() {
    assert_error("version 3\npacket P { @4 a uint8 }", "outside 1..3");
    assert_error("version 3\npacket P { @3..2 a uint8 }", "outside 1..3");
    assert_error("version 3\nconst C uint8 = 1\n@5 const C uint8 = 2", "outside 1..3");
}

#[test]
fn a_name_is_declared_once_per_version() {
    assert_error("version 3\npacket P { @1..2 a uint8, @2.. a uint16 }", "declared twice for version 2");
    assert_error("version 3\npacket P { a uint8, a uint16 }", "declared more than once");
    assert!(compile("version 3\npacket P { a uint8, @3 a uint16 }").is_ok());
}

#[test]
fn re_declarations_keep_the_kind_of_value() {
    assert_error("version 2\npacket P { a uint8, @2 a string(uint8) }", "incompatible type");
    assert_error("version 2\npacket P { a uint16, @2 a int32 }", "incompatible type");
    assert_error("version 2\npacket P { n uint8, a uint8[n], @2 a uint16[n] }", "cannot change type");
    assert_error("version 2\npacket P { a uint8, @2 a uint8[2] }", "stay an array");
    assert_error("version 2\npacket P { a uint8 = 1, @2 a uint16 }", "derived (`= ...`) in every version");
}

#[test]
fn overrides_change_existing_derived_fields() {
    assert_error("version 2\npacket P { a uint8, @2 b = 1 }", "does not have");
    assert_error("version 2\npacket P { a uint8, @2 a = 1 }", "not derived");
    assert!(compile("version 2\npacket P { a uint8 = 1, @2 a = 2, b uint8 == 3, @2 b == 4 }").is_ok());
}

#[test]
fn version_is_the_protocol_version_in_versioned_files() {
    // A field (or parameter) called `version` takes precedence in its packet.
    let m = compile("version 2\npacket P { version uint8, n uint8 = version, @2 a uint8 }").unwrap();
    assert!(m.packets[0].version_member.is_none());
    assert!(compile("version 2\npacket Q(version uint8) { a uint8[version] }").is_ok());
    assert_error("version 2\npacket P { @2 a uint8, ver uint8 = version }", "must come before");
    assert!(
        compile(
            "version 2\npacket P { ver uint8 = version, @2 a uint8, n uint8 = when version >= 2 then 1 otherwise 0 }"
        )
        .is_ok()
    );
}

#[test]
fn versioned_fields_can_be_measured() {
    assert!(compile("version 2\npacket P { n uint8 = sizeof(a), @2 a uint16, t uint8 }").is_ok());
    assert!(compile("version 2\npacket P { n uint8 = sizeof(a..t), a uint8, @2 a uint16, t uint8 }").is_ok());
    assert!(compile("version 2\npacket P { n uint8 = offsetof(t), a uint8, @2 a uint16, t uint8 }").is_ok());
    // A range must reach both of its ends in every version.
    assert_error(
        "version 2\npacket P { n uint8 = sizeof(a..b), a uint8, @2 a uint16, @2 b uint8 }",
        "does not exist in version 1",
    );
}

#[test]
fn versioned_headers_keep_a_frame_length() {
    let m = compile(
        "version 2\npacket F be { ver uint8 = version, @..1 len uint8 = sizeof(d), @2 len uint16 = sizeof(d), d bytes[len] }",
    )
    .unwrap();
    let f = m.frame_length(&m.packets[0]).expect("a frame length");
    assert!(f.version_header.is_some(), "the header's size depends on the version");
    // Without a version field, a header that differs has none.
    let m = compile("version 2\npacket F be { @..1 len uint8, @2 len uint16, d bytes[len] }").unwrap();
    assert!(m.frame_length(&m.packets[0]).is_none());
}

#[test]
fn union_arms_and_re_declared_unions() {
    assert_error(
        "version 2\npacket P { k uint8, b switch k { 1 => a uint8, @2 _ => r bytes[] } }",
        "`_` arm cannot have a version range",
    );
    assert_error(
        "version 2\npacket P { k uint8, b switch k { 1 => a uint8 }, @2 b switch k { 1 => a uint16 } }",
        "changes its type between versions",
    );
    assert!(compile("version 2\npacket P { k uint8, b switch k { 1 => a uint8, @2 1 => c uint16 } }").is_err());
    assert!(compile("version 2\npacket P { k uint8, b switch k { @..1 1 => a uint8, @2 1 => c uint16 } }").is_ok());
}

#[test]
fn a_subset_of_the_versions_leaves_the_others_out() {
    use packet_builder::ir::interp;
    let mut m = packet_builder::compile_file(std::path::Path::new("tests/specs/versions.packet")).unwrap();
    let all = m.packets.iter().find(|p| p.name == "Frame").unwrap().steps.len();
    m.restrict_versions(2, 3).unwrap();
    let frame = m.packets.iter().find(|p| p.name == "Frame").unwrap();
    assert!(frame.steps.len() < all, "gates for every version left are unwrapped");
    let v1 = [0x01, 0x10, 0x00, 0x05, 0x07, 0x03, 0x02, 0xaa, 0xbb, 0x01, 0x09];
    let e = interp::decode(&m, "Frame", &v1).unwrap_err();
    assert_eq!(e.kind, interp::ErrorKind::Constraint, "{}", e);
    let v3 = [0x03, 0x30, 0, 0, 0, 5, 0x01, 0x05, 0xab, 0x02, 0xaa, 0xbb, 0x12, 0x34, 0x01, 0x09];
    let value = interp::decode(&m, "Frame", &v3).unwrap();
    assert_eq!(interp::encode(&m, "Frame", &value).unwrap(), v3);
    assert!(m.clone().restrict_versions(0, 3).is_err());
    // Measurements of fields only other versions have still work.
    let mut v3 = m.clone();
    v3.restrict_versions(3, 3).unwrap();
    let sized = [0x03, 0, 0, 0, 0x0a, 0, 0, 0, 5, 0x12, 0x34, 0x02, 0x04, 0x0e, 0x09];
    let value = interp::decode(&v3, "Sized", &sized).unwrap();
    assert_eq!(interp::encode(&v3, "Sized", &value).unwrap(), sized);
}
