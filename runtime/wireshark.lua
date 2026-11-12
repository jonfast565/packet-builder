-- ---- packet-builder runtime (Wireshark Lua 5.4+) ----------------------------

-- Errors: decoding stops with a PbErr; the dissector shows it as a
-- malformed-packet expert item.
-- @lua_core

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
-- `tree`; returns the bytes it took, or nil and the error. `version`: the
-- protocol version to dissect as (files with versions; nil or 0: the one in
-- the data, or the latest).
local function pb_dissect(D, packet, F, X, tvb, tree, strict, version)
  local c = { r = pb_reader(tvb:raw()), tvb = tvb, F = F, X = X, strict = strict }
  if version and version > 0 then c.r.version = version end
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
-- from its header (for TCP reassembly), with its header size. latest: the
-- latest protocol version, for files with versions (adds a preference).
local function pb_register(D, make_fields, abbrev, name, packet, tables, heuristic, frame, header, latest)
  local proto = Proto(abbrev, name)
  if latest then
    proto.prefs.version = Pref.uint("Protocol version", 0,
      "The version to dissect as (1.." .. latest .. "); 0: the version in the data, or the latest")
  end
  local function version() return latest and proto.prefs.version or nil end
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
    local used = pb_dissect(D, packet, F, X, tvb, item, false, version())
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
      local used, err = pb_dissect(D, packet, F, X, rest, nil, false, version())
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
      if not pb_dissect(D, packet, F, X, tvb, nil, true, version()) then return false end
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
