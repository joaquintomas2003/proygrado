int_md = Proto("INT-MD", "INT-MD before TCP with new UDP header")

shim_type_and_npt = ProtoField.uint8("int-md.shim_type_and_npt", "Shim Type and NPT", base.HEX)
shim_length = ProtoField.uint8("int-md.shim_length", "Shim Length", base.HEX)
shim_proto = ProtoField.uint16("int-md.shim_proto", "Shim IP Proto", base.HEX)

int_md.fields = { shim_type_and_npt, shim_length, shim_proto }

function int_md.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = int_md.name

  local subtree = tree:add(int_md, buffer(), "INT-MD data")

  local offset = 0

  -- shim
  subtree:add(shim_type_and_npt, buffer(offset, 1))
  offset = offset + 1

  subtree:add(shim_length, buffer(offset, 1))
  offset = offset + 1

  subtree:add(shim_proto, buffer(offset, 2))
  offset = offset + 2
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(5000, int_md)
