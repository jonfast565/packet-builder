-- ---- packet-builder runtime (Lua 5.3+) ---------------------------------------

-- Errors: decoding and encoding raise a PbError table with error(e, 0)
-- (getmetatable(e) == PbError). e.kind is "incomplete" (the input ended
-- before the packet did), "invalid" (malformed data: a bad length, nesting
-- too deep, ...), "range" (a value does not fit in its field), "text" (a
-- string is not valid text, or holds a NUL where none is allowed),
-- "mismatch" (a length, derived field or checksum does not match the data)
-- or "constraint" (a value breaks a declared constraint); e.path says where
-- (`Packet.field[index].field`), e.bit is the reader or writer position,
-- e.msg the message and, for "incomplete", e.needed the least number of
-- extra input bits needed. tostring(e) gives "path: message".
-- @lua_core

local function pb_error(kind, msg, path, bit)
  return setmetatable({ kind = kind, msg = msg, path = path or "", bit = bit or 0 }, PbErr)
end

-- Running out of input also says how many more bits are needed (try_decode).
function Reader:short(bits, what)
  local left = self:remaining()
  if self.windows == 0 then
    local e = pb_error("incomplete",
      string.format("unexpected end of data: %s needs %d more bit(s), %d left", what, bits, left),
      self:path(), self.pos)
    e.needed = bits - left
    if e.needed < 1 then e.needed = 1 end
    error(e, 0)
  end
  self:fail("invalid", string.format("%s needs %d bit(s) but its window has %d left", what, bits, left))
end

-- Lua 5.3's utf8.len accepts UTF-16 surrogates (ED A0..ED BF); 5.4 and
-- later reject them, as every other runtime does.
local function pb_surrogate(s) return s:find("\237[\160-\191]") ~= nil end

local pb_core_text = Reader.text
function Reader:text(raw, enc, padded)
  local s = pb_core_text(self, raw, enc, padded)
  if enc == 0 and pb_surrogate(s) then self:fail("text", "invalid UTF-8") end
  return s
end

-- Byte arrays are strings; a table of byte values is accepted too.
local function pb_chars(v)
  if type(v) == "string" then return v end
  local parts = {}
  for i = 1, #v, 4096 do parts[#parts + 1] = string.char(table.unpack(v, i, math.min(i + 4095, #v))) end
  return table.concat(parts)
end

-- ---- writing ------------------------------------------------------------------

-- Builds the output (a table of byte values); integers may be written at
-- any bit position.
local Writer = {}
Writer.__index = Writer
for _, k in ipairs({ "path", "fail", "enter", "leave", "at", "at_index" }) do Writer[k] = Reader[k] end

local function pb_writer()
  -- base: where buf goes in the output, in bits (sub writers); placed:
  -- packets placed with `at`, for finish.
  return setmetatable({ buf = {}, pos = 0, base = 0, placed = {}, frames = {}, version = 0 }, Writer)
end

-- @versions{
Writer.version_or = Reader.version_or
Writer.set_version = Reader.set_version

-- The version a value carries in-band: used unless one is set already.
function Writer:adopt_version(v, min, latest)
  if self.version == 0 then self:set_version(v, min, latest) end
end
-- @versions}

function Writer:put_byte(b)
  if self.pos & 7 == 0 then
    self.buf[#self.buf + 1] = b
    self.pos = self.pos + 8
  else
    self:write_bits(b, 8)
  end
end

function Writer:write_bits(value, width)
  local buf, left = self.buf, width
  while left > 0 do
    local off = self.pos & 7
    if off == 0 then buf[#buf + 1] = 0 end
    local take = math.min(8 - off, left)
    local bits = (value >> (left - take)) & ((1 << take) - 1)
    buf[#buf] = buf[#buf] | (bits << (8 - off - take))
    self.pos = self.pos + take
    left = left - take
  end
end

function Writer:write_uint(v, n, little)
  for i = 0, n - 1 do
    local shift = little and 8 * i or 8 * (n - 1 - i)
    self:put_byte((v >> shift) & 0xff)
  end
end

function Writer:write_bytes(s)
  s = pb_chars(s)
  for i = 1, #s do self:put_byte(s:byte(i)) end
end

function Writer:write_float(v, width, little)
  if type(v) ~= "number" then self:fail("range", "the value is not a number") end
  self:write_bytes(string.pack((little and "<" or ">") .. (width == 32 and "f" or "d"), v))
end

function Writer:write_zero_bits(bits)
  while bits > 0 do
    if self.pos & 7 == 0 and bits >= 8 then
      self.buf[#self.buf + 1] = 0
      self.pos = self.pos + 8
      bits = bits - 8
    else
      local take = math.min(bits, 8 - (self.pos & 7))
      self:write_bits(0, take)
      bits = bits - take
    end
  end
end

-- A writer for a packet placed `offset` bytes after bit `start` of this
-- writer (the packet start), or after the start of the output (`root`).
function Writer:sub(start, offset, root)
  if root then start = 0 else start = self.base + start end
  if offset < 0 or start % 8 ~= 0 then
    self:fail("range", string.format("bad offset %d (from bit %d)", offset, start))
  end
  local s = pb_writer()
  s.version = self.version
  s.base = start + offset * 8
  for i, f in ipairs(self.frames) do s.frames[i] = { packet = f.packet, field = f.field, index = f.index } end
  return s
end

-- Keep what `s` wrote, for finish.
function Writer:place(s)
  self.placed[#self.placed + 1] = { at = s.base // 8, data = s.buf, path = self:path() }
  for _, p in ipairs(s.placed) do self.placed[#self.placed + 1] = p end
end

-- The output as a string, with every placed packet written at its offset:
-- past the end (zero-filling the gap), or over bytes that must already match.
function Writer:finish()
  local buf, placed = self.buf, self.placed
  for i, p in ipairs(placed) do p.order = i end
  table.sort(placed, function(a, b) return a.at < b.at or (a.at == b.at and a.order < b.order) end)
  for _, p in ipairs(placed) do
    for k = #buf + 1, p.at do buf[k] = 0 end
    for i, b in ipairs(p.data) do
      local k = p.at + i
      if k <= #buf then
        if buf[k] ~= b then
          error(pb_error("mismatch",
            string.format("the packet placed at byte %d does not match the bytes already there", p.at),
            p.path, (k - 1) * 8), 0)
        end
      else
        buf[k] = b
      end
    end
  end
  self.placed = {}
  return pb_chars(buf)
end

-- End a window of `size` bytes that started at bit `start`: the content
-- must fit (and fill it when `exact`); the rest is zero-filled.
function Writer:end_window(start, size, exact)
  local used = self.pos - start
  if size < 0 or used > size * 8 then
    self:fail("range", string.format("the content takes %d bit(s), more than its size of %d byte(s)", used, size))
  end
  if exact and used ~= size * 8 then
    self:fail("mismatch", string.format("the content takes %d bit(s) but must fill its %d byte(s)", used, size))
  end
  self:write_zero_bits(size * 8 - used)
end

-- Overwrite `n` bytes at bit position `at` (byte aligned).
function Writer:patch_uint(at, v, n, little)
  local start = at // 8
  for i = 0, n - 1 do
    local shift = little and 8 * i or 8 * (n - 1 - i)
    self.buf[start + i + 1] = (v >> shift) & 0xff
  end
end

-- Overwrite `width` bits at bit position `at`, MSB first.
function Writer:patch_bits(at, v, width)
  for i = 0, width - 1 do
    local bit = (v >> (width - 1 - i)) & 1
    local byte, off = (at + i) // 8 + 1, 7 - (at + i) % 8
    self.buf[byte] = (self.buf[byte] & ~(1 << off)) | (bit << off)
  end
end

-- Checksum `algo` of the output between two bit positions (whole bytes);
-- the bytes between hole_from and hole_to count as zero.
function Writer:checksum(algo, from, to, hole_from, hole_to)
  return Reader.checksum({ data = pb_chars(self.buf) }, algo, from, to, hole_from, hole_to)
end

function Writer:utf8_bytes(text)
  if type(text) ~= "string" or not utf8.len(text) or pb_surrogate(text) then self:fail("text", "the string is not valid UTF-8") end
  return text
end

local PB_ENCODINGS = { [0] = "UTF-8", "ASCII", "Latin-1", "UTF-16LE", "UTF-16BE" }

-- `text` (UTF-8) in encoding `enc` (see Reader:text).
function Writer:text_bytes(text, enc)
  self:utf8_bytes(text)
  if enc == 0 then return text end
  local out = {}
  for _, c in utf8.codes(text) do
    if enc == 1 and c >= 0x80 or enc == 2 and c > 0xff then
      self:fail("text", "the string is not valid " .. PB_ENCODINGS[enc])
    end
    if enc <= 2 then
      out[#out + 1] = string.char(c)
    else
      local units = { c }
      if c >= 0x10000 then units = { 0xD800 + ((c - 0x10000) >> 10), 0xDC00 + ((c - 0x10000) & 0x3ff) } end
      for _, u in ipairs(units) do
        if enc == 3 then out[#out + 1] = string.char(u & 0xff, u >> 8) else out[#out + 1] = string.char(u >> 8, u & 0xff) end
      end
    end
  end
  return table.concat(out)
end

-- Unsigned 64-bit decimal (Lua integers are signed).
local function pb_ustr(v)
  if v >= 0 then return string.format("%d", v) end
  local q = (v >> 1) // 5
  return string.format("%d%d", q, v - q * 10)
end

-- One variable-length integer (see Reader:read_varint).
function Writer:write_varint(kind, v)
  if kind == 5 then
    if math.ult(v, 0x80) then
      self:write_uint(v, 1, false)
    elseif math.ult(v, 0x8000) then
      self:write_uint(v | 0x8000, 2, false)
    else
      self:fail("range", pb_ustr(v) .. " does not fit in a varint15")
    end
    return
  end
  if kind == 4 then
    for code, n in ipairs({ 1, 2, 4, 8 }) do
      if math.ult(v, 1 << (8 * n - 2)) then
        self:write_uint(v | ((code - 1) << (8 * n - 2)), n, false)
        return
      end
    end
    self:fail("range", pb_ustr(v) .. " does not fit in a QUIC varint")
  end
  if kind == 1 then
    while true do
      local b = v & 0x7f
      v = v // 128
      local done = (v == 0 and b & 0x40 == 0) or (v == -1 and b & 0x40 ~= 0)
      self:write_uint(done and b or b | 0x80, 1, false)
      if done then return end
    end
  end
  if kind == 3 then
    local groups = { v & 0x7f }
    v = v >> 7
    while v ~= 0 do
      groups[#groups + 1] = (v & 0x7f) | 0x80
      v = v >> 7
    end
    for i = #groups, 1, -1 do self:write_uint(groups[i], 1, false) end
    return
  end
  if kind == 2 then v = (v << 1) ~ ((v >> 63) ~= 0 and -1 or 0) end
  while true do
    local b = v & 0x7f
    v = v >> 7
    if v == 0 then
      self:write_uint(b, 1, false)
      return
    end
    self:write_uint(b | 0x80, 1, false)
  end
end

function Writer:check_no_term(data, term)
  if pb_chars(data):find(term, 1, true) then self:fail("invalid", "the value contains its terminator") end
end

function Writer:check_fits(length, size)
  if length > size then self:fail("range", string.format("%d byte(s) do not fit in %d", length, size)) end
end

function Writer:check_no_nul(data)
  if data:find("\0", 1, true) then self:fail("text", "the string contains a NUL byte") end
end

function Writer:check_len(actual, expected)
  if actual ~= expected then
    self:fail("mismatch", string.format("%d element(s) but the length expression says %d", actual, expected))
  end
end

local function pb_int(w, v)
  if math.type(v) ~= "integer" then w:fail("range", "value " .. tostring(v) .. " is not an integer") end
end

function Writer:check_u(v, width)
  pb_int(self, v)
  if width < 64 and (v >> width) ~= 0 then
    self:fail("range", string.format("value %s does not fit in %d bit(s)", pb_ustr(v), width))
  end
end

function Writer:check_i(v, width)
  pb_int(self, v)
  if width < 64 and (v < -(1 << (width - 1)) or v >= (1 << (width - 1))) then
    self:fail("range", string.format("value %d does not fit in %d signed bit(s)", v, width))
  end
end

-- ---- values -------------------------------------------------------------------

-- A uint64 (its bit pattern in a Lua integer) as a float.
local function pb_u2f(v)
  if v >= 0 then return v + 0.0 end
  return ((v >> 1) | (v & 1)) * 2.0
end

local function pb_sumuf(seq)
  local t = 0.0
  for _, v in ipairs(seq) do t = t + pb_u2f(v) end
  return t
end

local function pb_produf(seq)
  local t = 1.0
  for _, v in ipairs(seq) do t = t * pb_u2f(v) end
  return t
end

-- A packet or union class: values are tables with it as metatable.
local function pb_class()
  local c = {}
  c.__index = c
  return c
end

-- Results of pcall(f, ...): f's results, or nil and the PbError it raised
-- (other errors are bugs and propagate).
local function pb_protect(ok, ...)
  if ok then return ... end
  local e = ...
  if getmetatable(e) == PbErr then return nil, e end
  error(e, 0)
end

-- try_decode: decode with reader `r`, or say how many more bytes are needed.
local function pb_try(decode, r)
  local ok, p = pcall(decode, r)
  if ok then return p, (r.pos + 7) // 8 end
  if getmetatable(p) == PbErr and p.kind == "incomplete" then return nil, math.max((p.needed + 7) // 8, 1) end
  error(p, 0)
end

-- ---- JSON ---------------------------------------------------------------------

local function pb_json_int(v) return string.format("%d", v) end

local function pb_json_float(v)
  v = v + 0.0
  if v ~= v then return "NaN" end
  if v == math.huge then return "inf" end
  if v == -math.huge then return "-inf" end
  local s
  for digits = 1, 17 do
    s = string.format("%." .. digits .. "g", v)
    if tonumber(s) == v then break end
  end
  if not s:find("[%.eEn]") then s = s .. ".0" end
  return s
end

local function pb_json_hex(v)
  return '"' .. (pb_chars(v):gsub(".", function(c) return string.format("%02x", c:byte()) end)) .. '"'
end

local function pb_json_str(s)
  return '"' .. s:gsub('[%c"\\]', function(c)
    if c == '"' then return '\\"' end
    if c == "\\" then return "\\\\" end
    return string.format("\\u%04x", c:byte())
  end) .. '"'
end

local function pb_json_list(seq, f)
  local parts = {}
  for i, v in ipairs(seq) do parts[i] = f(v) end
  return "[" .. table.concat(parts, ",") .. "]"
end

-- ---- generated packets ----------------------------------------------------------
