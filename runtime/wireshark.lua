-- ---- packet-builder runtime (Wireshark Lua 5.4+) ----------------------------

-- Errors: decoding stops with a PbErr; the dissector shows it as a
-- malformed-packet expert item.
local PbErr = {}
PbErr.__index = PbErr
PbErr.__tostring = function(e)
  if e.path ~= "" then return e.path .. ": " .. e.msg end
  return e.msg
end

local PB_MAX_DEPTH = 64

-- A reader over the frame's bytes (a Lua string); positions are in bits.
local Reader = {}
Reader.__index = Reader

local function pb_reader(data)
  return setmetatable({ data = data, pos = 0, limit = #data * 8, windows = 0, frames = {} }, Reader)
end

function Reader:path()
  local out = {}
  for i, f in ipairs(self.frames) do
    if i == 1 then out[#out + 1] = f.packet end
    if f.field == "" then break end
    out[#out + 1] = "." .. f.field
    if f.index then out[#out + 1] = "[" .. f.index .. "]" end
  end
  return table.concat(out)
end

function Reader:fail(kind, msg)
  error(setmetatable({ kind = kind, msg = msg, path = self:path(), bit = self.pos }, PbErr), 0)
end

function Reader:remaining() return self.limit - self.pos end

-- `bits` more bits are needed: incomplete at the end of the input, invalid
-- inside a window.
function Reader:short(bits, what)
  if self.windows == 0 then
    self:fail("incomplete", string.format("%s needs %d more bit(s), %d left", what, bits, self:remaining()))
  end
  self:fail("invalid", string.format("%s needs %d bit(s) but its window has %d left", what, bits, self:remaining()))
end

function Reader:need(bits)
  if bits < 0 or bits > self:remaining() then self:short(bits, "the field") end
end

function Reader:enter(packet)
  self.frames[#self.frames + 1] = { packet = packet, field = "" }
  if #self.frames > PB_MAX_DEPTH then
    self:fail("invalid", "packets nested more than " .. PB_MAX_DEPTH .. " deep")
  end
end

function Reader:leave() self.frames[#self.frames] = nil end

function Reader:at(field)
  local f = self.frames[#self.frames]
  f.field = field
  f.index = nil
end

function Reader:at_index(i) self.frames[#self.frames].index = i end

function Reader:push_limit(n)
  if n < 0 then self:fail("invalid", "negative size " .. n) end
  if n > self:remaining() // 8 then self:short(n * 8, "the window") end
  local saved = self.limit
  self.limit = self.pos + n * 8
  self.windows = self.windows + 1
  return saved
end

function Reader:pop_limit(saved, exact)
  if exact and self:remaining() > 0 then
    self:fail("invalid", self:remaining() .. " bit(s) left over in a field that must fill its size")
  end
  self.pos = self.limit
  self.limit = saved
  self.windows = self.windows - 1
end

function Reader:read_bits(width)
  self:need(width)
  local v, left = 0, width
  while left > 0 do
    local byte = self.data:byte((self.pos >> 3) + 1)
    local off = self.pos & 7
    local take = math.min(8 - off, left)
    v = (v << take) | ((byte >> (8 - off - take)) & ((1 << take) - 1))
    self.pos = self.pos + take
    left = left - take
  end
  return v
end

function Reader:read_uint(n, little)
  self:need(n * 8)
  if self.pos & 7 ~= 0 then
    local v = 0
    for i = 0, n - 1 do
      local b = self:read_bits(8)
      if little then v = v | (b << (8 * i)) else v = (v << 8) | b end
    end
    return v
  end
  local start = (self.pos >> 3) + 1
  local v = 0
  for i = 0, n - 1 do
    local b = self.data:byte(start + i)
    if little then v = v | (b << (8 * i)) else v = (v << 8) | b end
  end
  self.pos = self.pos + n * 8
  return v
end

function Reader:read_bytes(n)
  self:need(n * 8)
  local start = (self.pos >> 3) + 1
  self.pos = self.pos + n * 8
  return self.data:sub(start, start + n - 1)
end

function Reader:read_float(width, little)
  local raw = self:read_bytes(width // 8)
  return (string.unpack((little and "<" or ">") .. (width == 32 and "f" or "d"), raw))
end

function Reader:skip_bits(bits)
  self:need(bits)
  self.pos = self.pos + bits
end

-- Validate a decoded element count against the data that is left.
function Reader:count(n, elem_bits)
  if n < 0 then self:fail("invalid", "negative length " .. n) end
  if elem_bits > 0 and n > self:remaining() // elem_bits then self:short(n * elem_bits, "length " .. n) end
  return n
end

function Reader:read_cstring()
  local start = (self.pos >> 3) + 1
  local stop = self.data:find("\0", start, true)
  if not stop or stop > self.limit >> 3 then self:short(self:remaining() + 8, "the NUL-terminated string") end
  self.pos = stop * 8
  return self.data:sub(start, stop - 1)
end

function Reader:read_until(term, optional)
  local start = (self.pos >> 3) + 1
  local last = self.limit >> 3
  local stop = self.data:find(term, start, true)
  if stop and stop + #term - 1 <= last then
    self.pos = (stop - 1 + #term) * 8
    return self.data:sub(start, stop - 1)
  end
  if not optional then self:short(self:remaining() + 8, "the terminated field") end
  self.pos = self.limit
  return self.data:sub(start, last)
end

-- kind: 0 uleb128, 1 sleb128, 2 zigzag, 3 vlq, 4 quic
function Reader:read_varint(kind)
  if kind == 4 then
    local first = self:read_uint(1, false)
    local n = 1 << (first >> 6)
    local v = first & 0x3f
    if n > 1 then v = (v << (8 * (n - 1))) | self:read_uint(n - 1, false) end
    return v
  end
  local v, shift = 0, 0
  while true do
    local b = self:read_uint(1, false)
    if kind == 3 then
      if (v >> 57) ~= 0 then self:fail("invalid", "the varint does not fit in 64 bits") end
      v = (v << 7) | (b & 0x7f)
    else
      local last_ok
      if kind == 1 then last_ok = (b & 0x7f) == 0 or (b & 0x7f) == 0x7f else last_ok = (b & 0x7e) == 0 end
      if shift >= 64 or (shift == 63 and ((b & 0x80) ~= 0 or not last_ok)) then
        self:fail("invalid", "the varint does not fit in 64 bits")
      end
      v = v | ((b & 0x7f) << shift)
    end
    shift = shift + 7
    if (b & 0x80) == 0 then
      if kind == 1 and shift < 64 and (b & 0x40) ~= 0 then v = v | (-1 << shift) end
      break
    end
  end
  if kind == 2 then v = (v >> 1) ~ (-(v & 1)) end
  return v
end

-- Text in encoding enc (0 UTF-8, 1 ASCII, 2 Latin-1, 3 UTF-16LE, 4 UTF-16BE)
-- as UTF-8; padded cuts it at the first NUL character.
function Reader:text(raw, enc, padded)
  if enc <= 2 then
    if padded then
      local nul = raw:find("\0", 1, true)
      if nul then raw = raw:sub(1, nul - 1) end
    end
    if enc == 0 then
      if not utf8.len(raw) then self:fail("text", "invalid UTF-8") end
      return raw
    end
    local out = {}
    for i = 1, #raw do
      local b = raw:byte(i)
      if enc == 1 and b >= 0x80 then self:fail("text", "invalid ASCII") end
      out[#out + 1] = utf8.char(b)
    end
    return table.concat(out)
  end
  if #raw % 2 ~= 0 then self:fail("text", "invalid UTF-16 (an odd number of bytes)") end
  local function unit(i)
    local a, b = raw:byte(i, i + 1)
    if enc == 3 then return a | (b << 8) end
    return (a << 8) | b
  end
  local out, i = {}, 1
  while i <= #raw do
    local u = unit(i)
    if u == 0 and padded then break end
    if u >= 0xD800 and u <= 0xDBFF and i + 3 <= #raw then
      local lo = unit(i + 2)
      if lo >= 0xDC00 and lo <= 0xDFFF then
        u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)
        i = i + 2
      end
    end
    if u >= 0xD800 and u <= 0xDFFF then self:fail("text", "invalid UTF-16") end
    out[#out + 1] = utf8.char(u)
    i = i + 2
  end
  return table.concat(out)
end

-- Read `offset` bytes after bit `from` (the packet start, or 0 for the start
-- of the input) until jump_back; windows do not apply there.
function Reader:jump(from, offset)
  if offset < 0 or from % 8 ~= 0 or offset > #self.data or from + offset * 8 > #self.data * 8 then
    self:fail("invalid", "offset " .. offset .. " is past the end of the input")
  end
  local saved = { self.pos, self.limit, self.windows }
  self.pos, self.limit, self.windows = from + offset * 8, #self.data * 8, 0
  return saved
end

function Reader:jump_back(saved)
  self.pos, self.limit, self.windows = saved[1], saved[2], saved[3]
end

-- CRC parameters by algorithm number: width, polynomial (reflected for
-- reflected CRCs), initial value, reflected, final XOR.
local PB_CRC = {
  [0] = { 8, 0x07, 0, false, 0 },
  { 16, 0xA001, 0, true, 0 },
  { 16, 0x1021, 0xFFFF, false, 0 },
  { 16, 0x1021, 0, false, 0 },
  { 16, 0x8408, 0, true, 0 },
  { 16, 0xA001, 0xFFFF, true, 0 },
  { 32, 0xEDB88320, 0xFFFFFFFF, true, 0xFFFFFFFF },
  { 32, 0x82F63B78, 0xFFFFFFFF, true, 0xFFFFFFFF },
}

-- Checksum `algo` of the input between two bit positions (whole bytes); the
-- bytes between hole_from and hole_to count as zero.
function Reader:checksum(algo, from, to, hole_from, hole_to)
  local s, e, hs, he = from // 8, to // 8, hole_from // 8, hole_to // 8
  local function byte(i)
    if i >= hs and i < he then return 0 end
    return self.data:byte(i + 1) or 0
  end
  if algo < 8 then
    local width, poly, crc, reflected, xorout = table.unpack(PB_CRC[algo])
    local mask = (1 << width) - 1
    for i = s, e - 1 do
      local b = byte(i)
      if reflected then
        crc = crc ~ b
        for _ = 1, 8 do
          if crc & 1 ~= 0 then crc = (crc >> 1) ~ poly else crc = crc >> 1 end
        end
      else
        crc = crc ~ (b << (width - 8))
        for _ = 1, 8 do
          if crc & (1 << (width - 1)) ~= 0 then crc = ((crc << 1) ~ poly) & mask else crc = (crc << 1) & mask end
        end
      end
    end
    return (crc ~ xorout) & mask
  elseif algo == 8 then
    local total = 0
    for i = s, e - 1 do
      if (i - s) % 2 == 0 then total = total + (byte(i) << 8) else total = total + byte(i) end
    end
    while (total >> 16) ~= 0 do total = (total & 0xFFFF) + (total >> 16) end
    return (~total) & 0xFFFF
  elseif algo == 9 then
    local a, b = 0, 0
    for i = s, e - 1 do
      a = (a + byte(i)) % 255
      b = (b + a) % 255
    end
    return (b << 8) | a
  elseif algo == 10 then
    local total = 0
    for i = s, e - 1 do total = total + byte(i) end
    return total & 0xFF
  end
  local x = 0
  for i = s, e - 1 do x = x ~ byte(i) end
  return x
end

-- Expression helpers: 64-bit wrapping integers, as in every other runtime.
local function pb_div(a, b)
  if b == 0 then return 0 end
  if a == math.mininteger and b == -1 then return a end
  local q = a // b
  if q < 0 and q * b ~= a then q = q + 1 end
  return q
end

local function pb_mod(a, b)
  if b == 0 then return 0 end
  return math.fmod(a, b)
end

local function pb_shl(a, b)
  if b < 0 or b > 63 then return 0 end
  return a << b
end

local function pb_shr(a, b)
  if b < 0 then return 0 end
  if b > 63 then b = 63 end
  if a < 0 then return ~((~a) >> b) end
  return a >> b
end

local function pb_pow(a, b)
  if b < 0 then return 0 end
  local r = 1
  while b > 0 do
    if b & 1 == 1 then r = r * a end
    a = a * a
    b = b >> 1
  end
  return r
end

local function pb_fdiv(a, b) return a / b end

local function pb_sqrt(a)
  if a < 0 then return 0.0 / 0.0 end
  return math.sqrt(a)
end

local function pb_ftoi(v)
  if v ~= v then return 0 end
  if v >= 9.223372036854775807e18 then return math.maxinteger end
  if v <= -9.223372036854775808e18 then return math.mininteger end
  return math.tointeger(v < 0 and math.ceil(v) or math.floor(v))
end

local function pb_f32(v) return (string.unpack("<f", string.pack("<f", v))) end

local function pb_sext(v, width)
  if width < 64 and (v >> (width - 1)) & 1 == 1 then return v | (-1 << width) end
  return v
end

local function pb_trunc(v, width, signed)
  if width >= 64 then return v end
  v = v & ((1 << width) - 1)
  if signed then return pb_sext(v, width) end
  return v
end

local function pb_if(c, a, b)
  if c then return a end
  return b
end

-- Element i of an array (a table, or a string for byte arrays); 0 if out of range.
local function pb_at(seq, i)
  if i < 0 or i >= #seq then return 0 end
  if type(seq) == "string" then return seq:byte(i + 1) end
  return seq[i + 1]
end

local function pb_items(seq)
  if type(seq) == "string" then return { seq:byte(1, -1) } end
  return seq
end

local function pb_sum(seq)
  local t = 0
  for _, v in ipairs(pb_items(seq)) do t = t + v end
  return t
end

local function pb_prod(seq)
  local t = 1
  for _, v in ipairs(pb_items(seq)) do t = t * v end
  return t
end

local function pb_sumf(seq)
  local t = 0.0
  for _, v in ipairs(pb_items(seq)) do t = t + v end
  return t
end

local function pb_prodf(seq)
  local t = 1.0
  for _, v in ipairs(pb_items(seq)) do t = t * v end
  return t
end

local function pb_pad(offset, unit) return (unit - offset % unit) % unit end

-- ---- the protocol tree --------------------------------------------------------

-- The bytes covering bits [from, to), clamped to the frame.
local function pb_range(c, from, to)
  local len = c.tvb:len()
  local first = math.min(from // 8, len)
  local last = math.min((to + 7) // 8, len)
  -- Wireshark shows an empty item at the very end as missing.
  if first == last and first == len and len > 0 then first = len - 1; last = first end
  return c.tvb:range(first, last - first)
end

-- Values as Wireshark wants them for each field kind.
local function pb_wsval(kind, v)
  if kind == "u64" then return UInt64.fromhex(string.format("%016x", v)) end
  if kind == "i64" then return Int64.fromhex(string.format("%016x", v)) end
  return v
end

-- Add field `key` (read from bit `from` to the current position).
local function pb_add(c, tree, key, from, v)
  if not tree then return end
  local f = c.F[key]
  if f.kind == "bytes" then
    -- Wireshark reads bytes from the frame (exactly the value's bytes:
    -- a terminator after them is not part of the value).
    tree:add(f.field, pb_range(c, from, from + #v * 8))
    return
  end
  tree:add(f.field, pb_range(c, from, c.r.pos), pb_wsval(f.kind, v))
end

-- A calculated value: a generated item.
local function pb_gen(c, tree, key, v)
  if not tree then return end
  local f = c.F[key]
  local item = tree:add(f.field, pb_range(c, c.r.pos, c.r.pos), pb_wsval(f.kind, v))
  item:set_generated()
end

-- A subtree labelled `text`, starting at the current position; close it
-- with pb_close once its end is known.
local function pb_subtree(c, tree, text)
  if not tree then return nil end
  return tree:add(pb_range(c, c.r.pos, c.r.pos), text)
end

local function pb_close(c, item, from)
  if not item then return end
  local first = math.min(from // 8, c.tvb:len())
  local last = math.min((c.r.pos + 7) // 8, c.tvb:len())
  item:set_len(last - first)
end

local function pb_text(c, tree, text)
  if tree then tree:add(pb_range(c, c.r.pos, c.r.pos), text) end
end

-- Heuristic probes reject the packet on the first failed check.
local PbReject = {}

-- A failed field check or assertion: a warning (dissection goes on).
local function pb_check(c, tree, ok, msg)
  if ok then return end
  if c.strict then error(PbReject, 0) end
  if tree then tree:add_proto_expert_info(c.X.constraint, msg) end
end

-- A derived field that does not match the data.
local function pb_verify(c, tree, name, got, want)
  if got == want then return end
  if c.strict then error(PbReject, 0) end
  if tree then
    tree:add_proto_expert_info(c.X.mismatch,
      string.format("%s: 0x%x [incorrect, should be 0x%x]", name, got, want))
  end
end

-- Dissect packet `packet` (a function of D) from the start of `tvb` into
-- `tree`; returns the bytes it took, or nil and the error.
local function pb_dissect(D, packet, F, X, tvb, tree, strict)
  local c = { r = pb_reader(tvb:raw()), tvb = tvb, F = F, X = X, strict = strict }
  local ok, err = pcall(D[packet], c, tree, nil)
  if ok then return (c.r.pos + 7) // 8 end
  if err == PbReject then return nil, err end
  -- A bug rather than bad data. (Rethrowing an error raised by Wireshark's
  -- API crashes some Wireshark versions, so it is reported instead.)
  local text = getmetatable(err) == PbErr and tostring(err) or ("packet-builder internal error: " .. tostring(err))
  if tree then tree:add_proto_expert_info(X.malformed, text) end
  return nil, err
end

-- Register protocol `abbrev` for packet `packet`. tables: { {"tcp.port", 5190}, ... };
-- frame: an optional function(tvb, pinfo, offset) giving a packet's length
-- from its header (for TCP reassembly), with its header size.
local function pb_register(D, make_fields, abbrev, name, packet, tables, heuristic, frame, header)
  local proto = Proto(abbrev, name)
  local F = make_fields(abbrev)
  local list = {}
  for _, f in pairs(F) do list[#list + 1] = f.field end
  proto.fields = list
  local X = {
    malformed = ProtoExpert.new(abbrev .. ".malformed", "Malformed packet", expert.group.MALFORMED, expert.severity.ERROR),
    mismatch = ProtoExpert.new(abbrev .. ".mismatch", "Value does not match the data", expert.group.CHECKSUM, expert.severity.WARN),
    constraint = ProtoExpert.new(abbrev .. ".constraint", "Constraint violated", expert.group.PROTOCOL, expert.severity.WARN),
  }
  proto.experts = { X.malformed, X.mismatch, X.constraint }

  -- One packet at the start of tvb.
  local function one(tvb, pinfo, tree)
    pinfo.cols.protocol = name
    local item = tree:add(proto, tvb())
    local used = pb_dissect(D, packet, F, X, tvb, item, false)
    if used then item:set_len(used) end
    return used or tvb:len()
  end

  function proto.dissector(tvb, pinfo, tree)
    if frame and pinfo.can_desegment > 0 then
      dissect_tcp_pdus(tvb, tree, header, frame, one)
      return tvb:len()
    end
    -- Packets back to back; ask TCP for more data when one is cut off.
    local off = 0
    while off < tvb:len() do
      local rest = tvb:range(off):tvb()
      local used, err = pb_dissect(D, packet, F, X, rest, nil, false)
      if not used and err and err.kind == "incomplete" and pinfo.can_desegment > 0 then
        pinfo.desegment_offset = off
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return tvb:len()
      end
      used = one(rest, pinfo, tree)
      if used == 0 then break end
      off = off + used
    end
    return off
  end

  for _, t in ipairs(tables) do DissectorTable.get(t[1]):add(t[2], proto) end
  if heuristic then
    local function probe(tvb, pinfo, tree)
      if not pb_dissect(D, packet, F, X, tvb, nil, true) then return false end
      proto.dissector(tvb, pinfo, tree)
      return true
    end
    local transports = {}
    for _, t in ipairs(tables) do
      local transport = t[1]:match("^(%a+)%.")
      if transport == "tcp" or transport == "udp" then transports[transport] = true end
    end
    if not next(transports) then transports = { tcp = true, udp = true } end
    for transport in pairs(transports) do proto:register_heuristic(transport, probe) end
  end
  return proto, F, X
end

-- ---- generated packets ----------------------------------------------------------
