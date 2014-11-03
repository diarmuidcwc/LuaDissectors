dofile("common.lua")
-- trivial protocol example
-- declare our protocol
xnet_cbm_proto = Proto("xnet_cbm","xNet cbm104 Protocol")
-- create a function to dissect it
function xnet_cbm_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "xnet_cbm"
    local xnet_top_subtree = tree:add(xnet_cbm_proto,buffer(),"xNet Protocol Data")
	subtree = xnet_top_subtree:add(buffer(0,28),"xNet Header")
  local offset=0
	subtree:add(buffer(offset,4),"iNet Control: " .. tostring(buffer(offset,4)))
  offset = offset + 4
	subtree:add(buffer(offset,4),"StreamID: " .. tostring(buffer(offset,4)))
  offset = offset + 4
	subtree:add(buffer(offset,4),"Sequence Num: " .. buffer(offset,4):uint())
  offset = offset + 4
	subtree:add(buffer(offset,4),"Packet Len: " .. buffer(offset,4):uint())
	local xnet_payloadsize_in_bytes = buffer(offset,4):uint() - 28
	--local xnet_payloadsize_in_words = 32 - 14
  offset = offset + 4
	--subtree:add(buffer(offset,4),"Data Len: " .. xnet_payloadsize_in_words)
  ptptimesubtree = subtree:add(buffer(offset,8),"PTPTimeStamp")
  if ( buffer(offset,4):uint() > 1576800000 ) then
    ptptimesubtree:add(buffer(offset,4),"Date: ERROR. Some time after 2020")
  else
    ptptimesubtree:add(buffer(offset,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset,4):uint()))
	end
  ptptimesubtree:add(buffer(offset,4),"Seconds: " .. buffer(offset,4):uint())
  offset = offset + 4
	ptptimesubtree:add(buffer(offset,4),"nanoseconds: " .. buffer(offset,4):uint())
  offset = offset + 4
	subtree:add(buffer(offset,4),"xNET PIF: " .. tostring(buffer(offset,4)))
  offset = offset + 4
  datasubtree = xnet_top_subtree:add(buffer(offset,(xnet_payloadsize_in_bytes)),"xNet Payload")
  datasubtree:add(buffer(offset,2),"CBM_RdCounter: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"CBM_Report: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"txe1MsgInfo " .. tostring(buffer(offset,2)))
  offset = offset + 2
  local sbi_time = tostring(buffer(offset,6))
  local wall_time = sbi_to_walltime(sbi_time)
  datasubtree:add(buffer(offset,6),"txe1MsgSBITime: " .. os.date("!%H:%M:%S",wall_time))
  offset = offset + 6
  datasubtree:add(buffer(offset,2),"Message Count: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"BCU_TIME_DAYOFYEAR: " .. buffer(offset,2):uint())
  offset = offset + 2
  -- datasubtree:add(buffer(offset,2),"ETH102_PTP_DAYS: " .. buffer(offset,2):uint())
  -- offset = offset + 2
  -- local eth_time = tostring(buffer(offset,6))
  -- local eth_wall_time = sbi_to_walltime(eth_time)
  -- datasubtree:add(buffer(offset,6),"ETH102_WallTime: " .. os.date("%H:%M:%S %d %b %Y",eth_wall_time))
  -- offset = offset + 6
	end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(3023,xnet_cbm_proto)