use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use packet_builder::generators::fortran::{component, int_kind, kind_bits, module_name, real_kind, type_name};
use packet_builder::ir::{Module, ValueType};
use packet_builder::{GenOptions, Language};
use serde_json::Value;

use super::{Case, Target, packet, resolve_path, run, which};

pub struct FortranTarget;

/// The line that separates the program from the case data in `harness`.
const CASES: &str = "! @cases\n";

/// The compiler: `$FC`, or gfortran.
fn compiler() -> Option<PathBuf> {
    match std::env::var_os("FC") {
        Some(fc) if !fc.is_empty() => {
            let p = PathBuf::from(&fc);
            if p.is_absolute() { p.is_file().then_some(p) } else { which(&fc.to_string_lossy()) }
        }
        _ => which("gfortran"),
    }
}

/// A Fortran character literal (`'it''s'`); long text is split into pieces
/// joined with `//` so no source line gets too long.
fn f_text(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    let chars: Vec<char> = s.chars().collect();
    chars
        .chunks(60)
        .map(|c| format!("'{}'", c.iter().collect::<String>().replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(" // &\n      ")
}

/// The value `v` for a member of type `ty`.
fn set_value(ty: &ValueType, v: &Value) -> String {
    match (ty, v) {
        (ValueType::Str, Value::String(s)) => f_text(s),
        (ValueType::Float { width }, Value::Number(n)) => {
            format!("real({:e}_real64, {})", n.as_f64().expect("a number"), real_kind(*width))
        }
        (ValueType::Int { width, signed }, Value::Number(n)) => {
            let kind = int_kind(*width, *signed);
            let v = n.as_i64().unwrap_or_else(|| n.as_u64().expect("an integer") as i64);
            // A value the storage kind cannot hold (an out-of-range test
            // value) wraps as two's complement, as it would in C.
            let bits = kind_bits(kind);
            let v = if bits < 64 { (v << (64 - bits)) >> (64 - bits) } else { v };
            let lit = if v == i64::MIN {
                "(-9223372036854775807_int64 - 1_int64)".to_string()
            } else if v < 0 {
                format!("(-{}_int64)", -v)
            } else {
                format!("{}_int64", v)
            };
            format!("int({}, {})", lit, kind)
        }
        (ty, v) => panic!("cannot set a {:?} member to {}", ty, v),
    }
}

impl Target for FortranTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Fortran)
    }

    fn unavailable(&self) -> Option<String> {
        compiler().is_none().then(|| "no Fortran compiler ($FC or gfortran) found".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from("program pbh_main\n");
        let _ = writeln!(s, "  use {}", module_name(&GenOptions::default()));
        s.push_str("  use, intrinsic :: iso_fortran_env, only: int8, int16, int32, int64, real32, real64\n");
        s.push_str("  implicit none\n");
        s.push_str("  character(len=:), allocatable :: pbh_line\n");
        s.push_str("  integer(int8), allocatable :: pbh_d(:)\n");
        s.push_str("  integer :: pbh_u, pbh_ios, pbh_pk, pbh_ver, pbh_case, pbh_k, pbh_na, pbh_i\n");
        s.push_str("  integer(int64) :: pbh_a(16)\n");
        s.push_str("  open(newunit=pbh_u, file='cases.txt', status='old', action='read')\n");
        s.push_str("  do\n");
        s.push_str("    call pbh_read_line(pbh_u, pbh_line, pbh_ios)\n");
        s.push_str("    if (pbh_ios /= 0) exit\n");
        s.push_str("    pbh_k = index(pbh_line, ':')\n");
        s.push_str("    if (pbh_k == 0) cycle\n");
        s.push_str(
            "    read(pbh_line(1:pbh_k - 1), *) pbh_pk, pbh_ver, pbh_case, pbh_na, (pbh_a(pbh_i), pbh_i = 1, pbh_na)\n",
        );
        s.push_str("    call pbh_unhex(pbh_line(pbh_k + 1:), pbh_d)\n");
        s.push_str("    select case (pbh_pk)\n");
        for (i, p) in module.packets.iter().enumerate() {
            let a = if p.params.is_empty() { "" } else { ", pbh_a" };
            let _ = writeln!(s, "    case ({})\n      call pbh_run_{}(pbh_d, pbh_ver, pbh_case{})", i, i, a);
        }
        s.push_str("    end select\n");
        s.push_str("  end do\n");
        s.push_str("  close(pbh_u)\n\ncontains\n\n");

        s.push_str(
            "  subroutine pbh_read_line(u, line, ios)
    integer, intent(in) :: u
    character(len=:), allocatable, intent(out) :: line
    integer, intent(out) :: ios
    character(len=4096) :: buf
    integer :: n
    line = ''
    do
      read(u, '(a)', advance='no', iostat=ios, size=n) buf
      line = line // buf(1:n)
      if (is_iostat_eor(ios)) then
        ios = 0
        return
      end if
      if (ios /= 0) return
    end do
  end subroutine pbh_read_line

  subroutine pbh_unhex(h, b)
    character(len=*), intent(in) :: h
    integer(int8), allocatable, intent(out) :: b(:)
    integer :: i, v
    allocate(b(len_trim(h) / 2))
    do i = 1, size(b)
      read(h(2 * i - 1:2 * i), '(z2)') v
      if (v > 127) v = v - 256
      b(i) = int(v, int8)
    end do
  end subroutine pbh_unhex

  function pbh_err(e, pre) result(s)
    type(pb_error), intent(in) :: e
    character(len=*), intent(in) :: pre
    character(len=:), allocatable :: s
    type(pb_sb) :: sb
    call pb_sb_add(sb, ',\"' // pre // 'error\":')
    call pb_json_str(sb, e%message)
    call pb_sb_add(sb, ',\"' // pre // 'kind\":\"' // pb_kind_name(e%kind) // '\",\"' // pre // 'path\":')
    call pb_json_str(sb, e%path)
    s = pb_sb_text(sb)
  end function pbh_err

  function pbh_hex(b) result(s)
    integer(int8), allocatable, intent(in) :: b(:)
    character(len=:), allocatable :: s
    type(pb_sb) :: sb
    call pb_json_hex(sb, b)
    s = pb_sb_text(sb)
  end function pbh_hex
",
        );

        let mut sets: Vec<Vec<(usize, &Case)>> = vec![Vec::new(); module.packets.len()];
        let mut data = String::new();
        for (ci, c) in cases.iter().enumerate() {
            let pi = module.packets.iter().position(|p| p.name == c.packet).expect("packet exists");
            if !c.set.is_empty() {
                sets[pi].push((ci, c));
            }
            let args: String = c.args.iter().map(|a| format!(" {}", a)).collect();
            let _ = writeln!(data, "{} {} {} {}{} :{}", pi, c.version.unwrap_or(0), ci, c.args.len(), args, c.hex);
        }

        for (pi, p) in module.packets.iter().enumerate() {
            let t = type_name(&p.name);
            // Arguments of a packet with parameters, then the version.
            let args: String = p
                .params
                .iter()
                .enumerate()
                .map(|(k, x)| match x.ty {
                    ValueType::Int { width, signed } => format!(", int(pbh_a({}), {})", k + 1, int_kind(width, signed)),
                    _ => format!(", pbh_a({})", k + 1),
                })
                .collect();
            let ver = format!("{}{}", args, if p.versions.is_some() { ", pb_version=pbh_ver" } else { "" });
            let a = if p.params.is_empty() { "" } else { ", pbh_a" };
            let _ = writeln!(s, "\n  subroutine pbh_run_{}(pbh_d, pbh_ver, pbh_case{})", pi, a);
            s.push_str("    integer(int8), intent(in) :: pbh_d(:)\n    integer, intent(in) :: pbh_ver, pbh_case\n");
            if !p.params.is_empty() {
                s.push_str("    integer(int64), intent(in) :: pbh_a(:)\n");
            }
            let _ = writeln!(s, "    type({}) :: pbh_p", t);
            s.push_str("    type(pb_error) :: pbh_e\n    integer(int8), allocatable :: pbh_b(:)\n");
            s.push_str("    character(len=:), allocatable :: pbh_v, pbh_s\n    integer(int64) :: pbh_n\n");
            let _ = writeln!(s, "    call {}_decode(pbh_p, pbh_d, pbh_e{})", t, ver);
            s.push_str("    if (pbh_e%kind /= PB_OK) then\n");
            s.push_str("      write(*, '(a)') '{\"ok\":false' // pbh_err(pbh_e, '') // '}'\n");
            s.push_str("    else\n");
            if !sets[pi].is_empty() {
                s.push_str("      select case (pbh_case)\n");
                for (ci, c) in &sets[pi] {
                    let _ = writeln!(s, "      case ({})", ci);
                    for (path, v) in &c.set {
                        let chain = resolve_path(module, p, path);
                        let target: Vec<String> = chain.iter().map(|(_, m)| component(&m.name)).collect();
                        let ty = &chain.last().expect("a member").1.ty;
                        let _ = writeln!(s, "        pbh_p%{} = {}", target.join("%"), set_value(ty, v));
                    }
                }
                s.push_str("      end select\n");
            }
            let _ = writeln!(s, "      pbh_v = {}_to_json(pbh_p)", t);
            let _ = writeln!(s, "      call {}_encode(pbh_p, pbh_b, pbh_e{})", t, ver);
            s.push_str("      if (pbh_e%kind == PB_OK) then\n");
            s.push_str(
                "        write(*, '(a)') '{\"ok\":true,\"value\":' // pbh_v // ',\"encoded\":' // pbh_hex(pbh_b) // '}'\n",
            );
            s.push_str("      else\n");
            s.push_str(
                "        write(*, '(a)') '{\"ok\":true,\"value\":' // pbh_v // pbh_err(pbh_e, 'encode_') // '}'\n",
            );
            s.push_str("      end if\n    end if\n");
            if !p.params.is_empty() {
                s.push_str("    write(*, '(a)') '{}'\n");
                let _ = writeln!(s, "  end subroutine pbh_run_{}", pi);
                continue;
            }
            let tver = if p.versions.is_some() { ", pbh_ver" } else { "" };
            let _ = writeln!(s, "    call {}_try_decode(pbh_d, pbh_p, pbh_n, pbh_e{})", t, tver);
            s.push_str("    if (pbh_e%kind == PB_OK) then\n");
            s.push_str("      pbh_s = '{\"try\":\"done\",\"n\":' // pb_itoa(pbh_n)\n");
            s.push_str("    else if (pbh_e%kind == PB_INCOMPLETE) then\n");
            s.push_str("      pbh_s = '{\"try\":\"incomplete\",\"n\":' // pb_itoa(pbh_n)\n");
            s.push_str("    else\n      pbh_s = '{\"try\":\"error\"'\n    end if\n");
            if super::has_frame(module, p) {
                let _ = writeln!(s, "    call {}_frame_len(pbh_d, pbh_n, pbh_e)", t);
                s.push_str("    if (pbh_e%kind == PB_OK) then\n");
                s.push_str("      pbh_s = pbh_s // ',\"frame\":' // pb_itoa(pbh_n)\n");
                s.push_str("    else if (pbh_e%kind == PB_INCOMPLETE) then\n");
                s.push_str("      pbh_s = pbh_s // ',\"frame\":null'\n");
                s.push_str("    else\n      pbh_s = pbh_s // ',\"frame\":\"error\"'\n    end if\n");
            }
            s.push_str("    write(*, '(a)') pbh_s // '}'\n");
            let _ = writeln!(s, "  end subroutine pbh_run_{}", pi);
        }
        s.push_str("\nend program pbh_main\n");
        s.push_str(CASES);
        s.push_str(&data);
        // Keep the packet lookup honest: every case names a known packet.
        for c in cases {
            let _ = packet(module, &c.packet);
        }
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        let (program, data) = harness.split_once(CASES).expect("harness has a cases marker");
        let module = format!("{}.f90", module_name(&GenOptions::default()));
        fs::write(dir.join(&module), generated).unwrap();
        fs::write(dir.join("harness.f90"), program).unwrap();
        fs::write(dir.join("cases.txt"), data).unwrap();
        let fc = compiler().ok_or("no Fortran compiler")?;
        // -fcheck=all: bounds, allocation and pointer checks abort the run.
        run(
            Command::new(&fc).current_dir(dir).args([
                "-std=f2008",
                "-Wall",
                "-fcheck=all",
                "-g",
                "-o",
                "harness",
                &module,
                "harness.f90",
            ]),
            "gfortran",
        )?;
        run(Command::new(dir.join("harness")).current_dir(dir), "fortran harness")
    }
}
