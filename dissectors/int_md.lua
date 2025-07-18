int_md = Proto("INT-MD", "INT-MD before TCP with new UDP header")

-- INT Shim Header
-- byte 0
shim_type = ProtoField.uint8("int-md.shim_type", "Shim Type", base.DEC, nil, 0xF0) -- bits 7-4
shim_npt = ProtoField.uint8("int-md.shim_npt", "Shim NPT", base.DEC, nil, 0x0C) -- bits 3-2

-- byte 1
shim_length = ProtoField.uint8("int-md.shim_length", "Shim Length", base.DEC)

-- byte 2 and 3
shim_proto = ProtoField.uint16("int-md.shim_proto", "Shim IP Proto", base.DEC)

-- INT-MD Metadata Header
-- byte 0
ver = ProtoField.uint8("int-md.version", "Version", base.DEC, nil, 0xF0) -- bits 7-4
d   = ProtoField.bool("int-md.discard", "Discard (D)", 8, nil, 0x08) -- bit 3
e   = ProtoField.bool("int-md.hc_exceeded", "Hop Count Exceeded (E)", 8, nil, 0x04) -- bit 2
m   = ProtoField.bool("int-md.mtu_exceeded", "MTU Exceeded (M)", 8, nil, 0x02) -- bit 1
-- 1 bit reserved

-- byte 1
-- Whole byte reserved

-- byte 2
-- 3 bits reserved
hop_ml = ProtoField.uint8("int-md.hop_ml", "Per-hop Metadata Length", base.DEC, nil, 0x1F) -- bits 4-0

-- byte 3
rhc = ProtoField.uint8("int-md.rhc", "Remaining Hop Count", base.DEC) -- whole byte

-- bytes 4-5
instruction_bitmap = ProtoField.uint16("int-md.instruction_bitmap", "Instruction Bitmap", base.HEX)

-- bytes 6-7
domain_specific_id = ProtoField.uint16("int-md.domain_specific_id", "Domain Specific Id", base.HEX)

-- bytes 8-9
ds_instruction = ProtoField.uint16("int-md.ds_instruction", "DS Instruction", base.HEX)

-- bytes 10-11
ds_flags = ProtoField.uint16("int-md.ds_flags", "DS Flags", base.HEX)

int_md.fields = { shim_type, shim_npt, shim_length, shim_proto,
                  ver, d, e, m, hop_ml, rhc,
                  instruction_bitmap, domain_specific_id,
                  ds_instruction, ds_flags
                }

function int_md.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = int_md.name

  local subtree = tree:add(int_md, buffer(), "INT-MD data")

  local offset = 0

  -- shim
  local shim_buf = buffer(offset, 1)
  subtree:add(shim_type, shim_buf)
  subtree:add(shim_npt, shim_buf)
  offset = offset + 1

  local shim_length_buf = buffer(offset, 1)
  subtree:add(shim_length, shim_length_buf)
  offset = offset + 1

  subtree:add(shim_proto, buffer(offset, 2))
  offset = offset + 2

  -- metadata header
  local metadata_byte0 = buffer(offset,1)
  subtree:add(ver, metadata_byte0)
  subtree:add(d, metadata_byte0)
  subtree:add(e, metadata_byte0)
  subtree:add(m, metadata_byte0)
  offset = offset + 1

  offset = offset + 1 -- reserved byte

  local metadata_byte2 = buffer(offset, 1)
  subtree:add(hop_ml, metadata_byte2)
  offset = offset + 1

  local metadata_byte3 = buffer(offset, 1)
  subtree:add(rhc, metadata_byte3)
  offset = offset + 1

  local instruction_bitmap = buffer(offset, 2):uint()
  local instruction_fields = {
    [0] = "Node ID",
    [1] = "L1 Ingress + Egress Interface IDs",
    [2] = "Hop latency",
    [3] = "Queue ID + Queue occupancy",
    [4] = "Ingress timestamp",
    [5] = "Egress timestamp",
    [6] = "L2 Ingress + Egress Interface IDs",
    [7] = "Egress interface Tx utilization",
    [8] = "Buffer ID + Buffer occupancy",
    [15] = "Checksum Complement"
  }
  local bitmap_tree = subtree:add("Instruction Bitmap Set Bits:")
  for i = 0, 15 do
    local mask = bit.lshift(1, 15 - i)  -- bit 0 is MSB
    if bit.band(instruction_bitmap, mask) ~= 0 then
      local label = instruction_fields[i] or ("Reserved bit " .. i)
      bitmap_tree:add(string.format("Bit %d: %s", i, label))
    end
  end
  offset = offset + 2

  subtree:add(domain_specific_id, buffer(offset, 2))
  offset = offset + 2

  subtree:add(ds_instruction, buffer(offset, 2))
  offset = offset + 2

  subtree:add(ds_flags, buffer(offset, 2))
  offset = offset + 2

  -- metadata stack
  local metadata_bit_lengths = {
    [0] = 4,  -- Node ID
    [1] = 4,  -- L1 Interface IDs
    [2] = 4,  -- Hop Latency
    [3] = 4,  -- Queue ID + occupancy
    [4] = 8,  -- Ingress timestamp
    [5] = 8,  -- Egress timestamp
    [6] = 8,  -- L2 Interface IDs
    [7] = 4,  -- Tx utilization
    [8] = 4,  -- Buffer ID + occupancy
    [15] = 4  -- Checksum complement
  }

  local hop_ml_val = bit.band(metadata_byte2:uint(), 0x1F)
  local per_hop_len = hop_ml_val * 4  -- in bytes

  -- total number of hops = (shim.len - metada_header_len) / hop_ml
  -- = (shim_len_val - 3) / hop_ml_val
  local shim_len_val = shim_length_buf:uint()
  local total_hops = (shim_len_val - 3) / hop_ml_val

  local rhc_val = metadata_byte3:uint()
  local present_hops = total_hops - rhc_val

  for hop = 1, present_hops + 1 do
    local hop_buf = buffer(offset, per_hop_len)
    local hop_tree = subtree:add("Hop Metadata #" .. hop .. " (" .. per_hop_len .. " bytes)")

    local meta_offset = 0
    for i = 0, 15 do
      local mask = bit.lshift(1, 15 - i)
      if bit.band(instruction_bitmap, mask) ~= 0 then
        local len = metadata_bit_lengths[i]
        local label = instruction_fields[i] or ("Reserved Bit " .. i)
        local field_buf = hop_buf(meta_offset, len)
        local field_value = len == 8 and field_buf:uint64() or field_buf:uint()
        local display_value = (len == 8) and tostring(field_value) or field_value
        hop_tree:add(field_buf, string.format("%s: %s", label, display_value))
        meta_offset = meta_offset + len
      end
    end

    offset = offset + per_hop_len
  end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(5000, int_md)
