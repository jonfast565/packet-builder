//! Generates a parser for every spec in tests/specs in every target language,
//! builds it with the language's own toolchain and runs the test vectors.
//! Languages whose toolchain is not installed are skipped (set
//! PB_REQUIRE_ALL=1 to make that an error).

mod harness;

#[test]
fn rust_parsers_work() {
    harness::run_target(&harness::rust::RustTarget);
}

#[test]
fn c_parsers_work() {
    harness::run_target(&harness::c::CTarget);
}

#[test]
fn go_parsers_work() {
    harness::run_target(&harness::go::GoTarget);
}

#[test]
fn python_parsers_work() {
    harness::run_target(&harness::python::PythonTarget);
}

#[test]
fn csharp_parsers_work() {
    harness::run_target(&harness::csharp::CSharpTarget);
}

#[test]
fn zig_parsers_work() {
    harness::run_target(&harness::zig::ZigTarget);
}
