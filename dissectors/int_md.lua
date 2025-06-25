int_md = Proto("INT-MD", "INT-MD before TCP with new UDP header")

int_md.fields = {}

function int_md.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = int_md.name

  local subtree = tree:add(int_md, buffer(), "INT-MD data")
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(5000, int_md)
