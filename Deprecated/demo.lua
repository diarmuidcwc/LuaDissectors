dofile("common.lua")
-- trivial protocol example
-- declare the three protocols defined here
xnet_cbm_104_proto = Proto("xnet_cbm_104_demo","xNet Demo cbm104 Protocol")
xnet_cbm_103_proto = Proto("xnet_cbm_103_demo","xNet Demo cbm103 Protocol")
xnet_abm102_proto = Proto("xnet_abm102_demo","xNet Demo ABM102 Protocol")
  


-------------------------------
--   XNET CBM104 DATA  --------
---------------------------------
function xnet_cbm_104_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "xnet_cbm_104"
    local xnet_top_subtree = tree:add(xnet_cbm_104_proto,buffer(),"xNet Demo CBM104 Data")
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
  
  -- CBM104 data
  datasubtree = xnet_top_subtree:add(buffer(offset,(xnet_payloadsize_in_bytes)),"xNet Payload")
  datasubtree:add(buffer(offset,2),"CBM_RdCounter: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"CBM_Report: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  
  -- slot data
  local slot = 1
  repeat
    slotsubtree = datasubtree:add(buffer(offset,22),"Parser Block: " .. slot)
    slotsubtree:add(buffer(offset,2),"Message Info " .. tostring(buffer(offset,2)))
    -- a more readable version
    local info_txt = info_to_txt(buffer(offset,1):uint())
    local open_slot = buffer(offset,2):uint() % 512
    slotsubtree:add(buffer(offset,2),"Slot " .. open_slot .. " (" .. info_txt .. ")")
    
    offset = offset + 2
    local sbi_time = tostring(buffer(offset,6))
    local wall_time = sbi_to_walltime(sbi_time)
    slotsubtree:add(buffer(offset,6),"Message Time: " .. os.date("!%H:%M:%S",wall_time))
    offset = offset + 6
    slotsubtree:add(buffer(offset,2),"Message Count: " .. buffer(offset,2):uint())
    offset = offset + 2
    slotsubtree:add(buffer(offset,2),"Message Size: " .. buffer(offset,2):uint())
    offset = offset + 2
    local word_count = 0
    repeat
      slotsubtree:add(buffer(offset,4),"Message Word (" .. word_count .. "):" ..  tostring(buffer(offset,4)))
      offset = offset + 4
      word_count = word_count + 1
    until (word_count == 3)
    slot = slot + 1
  until (slot == 3)
	end
  
  
-------------------------------
--   XNET CBM103 DATA  --------
---------------------------------

function xnet_cbm_103_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "xnet_cbm_103"
    local xnet_top_subtree = tree:add(xnet_cbm_103_proto,buffer(),"xNet CBM103 Data")
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
  
  -- CBM103 data
  datasubtree = xnet_top_subtree:add(buffer(offset,(xnet_payloadsize_in_bytes)),"xNet Payload")
  datasubtree:add(buffer(offset,2),"ReadCounter: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"Report: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  
  -- slot data
  local slot = 1
  repeat
    slotsubtree = datasubtree:add(buffer(offset,22),"Parser Block: " .. slot)
    slotsubtree:add(buffer(offset,2),"Message Info " .. tostring(buffer(offset,2)))
    -- a more readable version
    local info_txt = info_to_txt(buffer(offset,1):uint())
    local open_slot = buffer(offset,2):uint() % 512
    slotsubtree:add(buffer(offset,2),"Slot " .. open_slot .. " (" .. info_txt .. ")")
    
    
    offset = offset + 2
    local sbi_time = tostring(buffer(offset,6))
    local wall_time = sbi_to_walltime(sbi_time)
    slotsubtree:add(buffer(offset,6),"Message Time: " .. os.date("!%H:%M:%S",wall_time))
    offset = offset + 6
    slotsubtree:add(buffer(offset,2),"Message Count: " .. buffer(offset,2):uint())
    offset = offset + 2
    slotsubtree:add(buffer(offset,2),"Message Size: " .. buffer(offset,2):uint())
    offset = offset + 2
    local word_count = 0
    repeat
      slotsubtree:add(buffer(offset,4),"Message Word (" .. word_count .. "):" ..  tostring(buffer(offset,4)))
      offset = offset + 4
      word_count = word_count + 1
    until (word_count == 16)
    slot = slot + 1
  until (slot == 3)
	end 

 
-------------------------------
--   XNET ABM102 DATA  --------
---------------------------------

function xnet_abm102_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "xnet_abm102"
    local xnet_top_subtree = tree:add(xnet_abm102_proto,buffer(),"xNet Protocol Data")
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
  
  -- DATA ---
  local slot = 1
  datasubtree = xnet_top_subtree:add(buffer(offset,(xnet_payloadsize_in_bytes)),"xNet Payload")
  repeat 
    slotsubtree = datasubtree:add(buffer(offset,12),"Parser Block: " .. slot)
    local error_code = (buffer(offset,1):uint() / 2) % 8
    slotsubtree:add(buffer(offset,2),"Error Code: " .. error_code)
    local quad_bytes = (buffer(offset,2):uint())
    slotsubtree:add(buffer(offset,2),"Quad Bytes: " .. quad_bytes)
    offset = offset + 2
    slotsubtree:add(buffer(offset,1),"Message Count: " .. buffer(offset,1):uint())
    offset = offset + 1
    slotsubtree:add(buffer(offset,1),"Bus ID: " .. buffer(offset,1):uint())
    offset = offset + 1
    slotsubtree:add(buffer(offset,4),"Elapsed Time: " .. buffer(offset,4):uint())
    offset = offset + 4
    local quad_count = 0
    repeat
      slotsubtree:add(buffer(offset,4),"Message Data: " ..  tostring(buffer(offset,4)))
      offset = offset + 4
      quad_count = quad_count + 1
    until (quad_count == quad_bytes-2)
    slot = slot + 1
  until (offset == xnet_payloadsize_in_bytes+28)
  
	end
  
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- map the dissectors to the port the eth drives each packet
udp_table:add(4444,xnet_cbm_104_proto)
udp_table:add(3333,xnet_cbm_103_proto)
udp_table:add(5555,xnet_abm102_proto)
