dofile("common.lua")
-- trivial protocol example
-- declare our protocol
tcg102_proto = Proto("tcg102","tcg102 Protocol")
-- create a function to dissect it
function tcg102_proto.dissector(buffer,pinfo,tree)
  pinfo.cols.protocol = "tcg102"
  local tcg102_top_subtree = tree:add(tcg102_proto,buffer(),"tcg102 Protocol Data")
	subtree = tcg102_top_subtree:add(buffer(0,13),"tcg102 IENA Header")
  offset = 0
	subtree:add(buffer(offset,2),"tcg102 Key: " .. tostring(buffer(offset,2)))
  offset = offset + 2
	subtree:add(buffer(offset,2),"Size: " .. buffer(offset,2):uint())
  local sizeinwords = buffer(offset,2):uint()
  offset = 14
  subtree = tcg102_top_subtree:add(buffer(offset,8),"tcg102 Data")
  subtree:add(buffer(offset,2),"TCG102C_DOY: "               .. buffer(offset,2):uint())
  offset = offset + 2
  local tcg_sbi_time = tostring(buffer(offset,6))
  local tcg_wall_time = sbi_to_walltime(tcg_sbi_time)
  subtree:add(buffer(offset,6),"TCG_SBITime: " .. os.date("!%H:%M:%S",tcg_wall_time))
  offset = offset + 6


end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(4788,tcg102_proto)