use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use packet_builder::Language;
use packet_builder::generators::common::lua::index;
use packet_builder::ir::Module;
use serde_json::Value;

use super::{Case, Target, packet, quote, resolve_path, run, which};

pub struct LuaTarget;

/// The interpreter: `$LUA`, or `lua` on the PATH.
fn lua() -> Option<PathBuf> {
    match std::env::var_os("LUA") {
        Some(l) => {
            let p = PathBuf::from(&l);
            if p.is_file() { Some(p) } else { which(&l.to_string_lossy()) }
        }
        None => which("lua"),
    }
}

/// A `set` value: uint64 values above i64::MAX as hex, since Lua reads
/// larger decimal literals as floats.
fn set_literal(v: &Value) -> String {
    match v {
        Value::Number(n) if n.as_i64().is_none() && n.as_u64().is_some() => format!("0x{:x}", n.as_u64().unwrap()),
        Value::Number(n) => n.to_string(),
        Value::String(s) => quote(s),
        other => panic!("set values must be numbers or strings, got {}", other),
    }
}

/// The driver: one generic runner over a table of cases (a function per
/// case would hit Lua's limits on large specs).
const RUNNER: &str = r#"package.path = "./?.lua;" .. package.path
local M = require("packets")

local function unhex(h) return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end)) end
local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local function js(s)
  return '"' .. s:gsub('[%c"\\]', function(c)
    if c == '"' then return '\\"' end
    if c == "\\" then return "\\\\" end
    return string.format("\\u%04x", c:byte())
  end) .. '"'
end

-- The PbError a pcall caught; anything else is a bug and is raised again.
local function caught(e)
  if getmetatable(e) ~= M.PbError then error(e, 0) end
  return e
end

local function fields(e, pre)
  return string.format(',"%serror":%s,"%skind":%s,"%spath":%s', pre, js(tostring(e)), pre, js(e.kind), pre, js(e.path))
end

-- f(x, args..., version): parameters come before the version.
local function call(f, x, args, version)
  local t = { x }
  for i, a in ipairs(args) do t[i + 1] = a end
  t[#args + 2] = version
  return pcall(f, (table.unpack or unpack)(t, 1, #args + 2))
end

local function run(C, h, version, set, frame, args)
  local d = unhex(h)
  local ok, p = call(C.decode, d, args, version)
  if not ok then
    print('{"ok":false' .. fields(caught(p), "") .. "}")
  else
    if set then set(p) end
    local v = C.to_json(p)
    local ok2, b = call(C.encode, p, args, version)
    if ok2 then
      print('{"ok":true,"value":' .. v .. ',"encoded":"' .. hex(b) .. '"}')
    else
      print('{"ok":true,"value":' .. v .. fields(caught(b), "encode_") .. "}")
    end
  end
  -- Packets with parameters have no stream helpers.
  if #args > 0 then print("{}") return end
  local s
  local ok3, q, n = pcall(C.try_decode, d, version)
  if not ok3 then
    caught(q)
    s = '{"try":"error"'
  else
    s = string.format('{"try":"%s","n":%d', q ~= nil and "done" or "incomplete", n)
  end
  if frame then
    local ok4, f = pcall(C.frame_len, d)
    if not ok4 then
      caught(f)
      s = s .. ',"frame":"error"'
    else
      s = s .. ',"frame":' .. (f == nil and "null" or string.format("%d", f))
    end
  end
  print(s .. "}")
end

"#;

impl Target for LuaTarget {
    fn language(&self) -> Option<Language> {
        Some(Language::Lua)
    }

    fn unavailable(&self) -> Option<String> {
        lua().is_none().then(|| "lua not found (set $LUA or put lua on the PATH)".into())
    }

    fn harness(&self, module: &Module, cases: &[Case], _zero_copy: bool) -> String {
        let mut s = String::from(RUNNER);
        s.push_str("local cases = {\n");
        for c in cases {
            let p = packet(module, &c.packet);
            let ver = c.version.map(|v| v.to_string()).unwrap_or_else(|| "nil".into());
            let set = if c.set.is_empty() {
                "nil".to_string()
            } else {
                let body: String = c
                    .set
                    .iter()
                    .map(|(path, v)| {
                        let place: String =
                            resolve_path(module, p, path).into_iter().map(|(_, m)| index(&m.name)).collect();
                        format!(" p{} = {};", place, set_literal(v))
                    })
                    .collect();
                format!("function(p){} end", body)
            };
            let _ = writeln!(
                s,
                "  {{ M{}, \"{}\", {}, {}, {}, {{ {} }} }},",
                index(&p.name),
                c.hex,
                ver,
                set,
                super::has_frame(module, p),
                c.arg_list()
            );
        }
        s.push_str("}\n\nfor _, c in ipairs(cases) do run(c[1], c[2], c[3], c[4], c[5], c[6]) end\n");
        s
    }

    fn build_and_run(&self, dir: &Path, generated: &str, harness: &str) -> Result<String, String> {
        fs::write(dir.join("packets.lua"), generated).unwrap();
        fs::write(dir.join("main.lua"), harness).unwrap();
        let lua = lua().ok_or("lua not found")?;
        run(Command::new(lua).current_dir(dir).arg("main.lua"), "lua harness")
    }
}
