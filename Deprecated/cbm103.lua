dofile("common.lua")
-- trivial protocol example
-- declare our protocol
cbm103_proto = Proto("cbm103","cbm103 Protocol")
-- create a function to dissect it
function cbm103_proto.dissector(buffer,pinfo,tree)
  pinfo.cols.protocol = "cbm103"
  local cbm103_top_subtree = tree:add(cbm103_proto,buffer(),"CBM103 Protocol Data")
	subtree = cbm103_top_subtree:add(buffer(0,13),"CBM103 IENA Header")
  offset = 0
	subtree:add(buffer(offset,2),"cbm103 Key: " .. tostring(buffer(offset,2)))
  offset = offset + 2
	subtree:add(buffer(offset,2),"Size: " .. buffer(offset,2):uint())
    local iena_size_in_words = buffer(offset,2):uint()
  offset = offset + 2
    
    subtree:add(buffer(offset,6),"Time: " .. tostring(buffer(offset,6)))
    -- iena time is time since first sec of this year
    -- lua can't handle 6byte integers so first truncate the last 2 bytes and then compensate for that later
    -- probably something lost in the rounding but good enough
    local time_in_usec = buffer(offset,4):uint() -- this is actually usec divided by 2^16
    local ostime_this_year = os.time{year=2010, month=1, day=1, hour=0, min=0, sec=0} -- get the 1st jan this year
    subtree:add(buffer(offset,6),"Date: " .. os.date("!%H:%M:%S %d %b %Y",(ostime_this_year + time_in_usec/15.2587890625)))
    offset = offset + 6
    subtree:add(buffer(offset,1),"Key Status: " .. tostring(buffer(offset,1)))
    offset = offset + 1
    subtree:add(buffer(offset,1),"N2 Status: " .. tostring(buffer(offset,1)))
    offset = offset + 1
    subtree:add(buffer(offset,2),"Seq Number: " .. buffer(offset,2):uint())
    offset = offset + 2  
  local sizeinwords = buffer(offset,2):uint()
  subtree = cbm103_top_subtree:add(buffer(offset,(iena_size_in_words-8)*2),"CBM103 Data")
  subtree:add(buffer(offset,2),"Read Count: "               .. buffer(offset,2):uint())
  offset = offset + 2
  subtree:add(buffer(offset,2),"Report: "           .. tostring(buffer(offset,2)))
  offset = offset + 2
  local total_slots = (sizeinwords - 8) / 39
  local slot_count = 0
  repeat
    slot_count = slot_count + 1
    local info_txt = info_to_txt(buffer(offset,1):uint())
    offset = offset + 1
    local open_slot = buffer(offset-1,2):uint() % 512
    local slot_subtree = subtree:add(cbm103_proto,buffer(offset-1,76),"Slot " .. open_slot .. " (" .. info_txt .. ")")
    slot_subtree:add(buffer(offset-1,1),"Slot Info: "        .. info_txt)
    offset = offset + 1
    local msg_sbi_time = tostring(buffer(offset,6))
    local msg_wall_time = sbi_to_walltime(msg_sbi_time)
    slot_subtree:add(buffer(offset,6),"BCU_SBITime: " .. os.date("!%H:%M:%S",msg_wall_time))
    offset = offset + 6
    slot_subtree:add(buffer(offset,2),"Message Count: "             .. buffer(offset,2):uint())
    offset = offset + 2
    slot_subtree:add(buffer(offset,2),"Message Size: "              .. buffer(offset,2):uint())
    offset = offset + 2
    slot_subtree:add(buffer(offset,1),"Slot HDR2: "        .. tostring(buffer(offset,1)))
    offset = offset + 1
    local msg_len = buffer(offset,1):uint() % 64
    slot_subtree:add(buffer(offset,1),"MSG Len= "        .. msg_len)
    local msg_seq = math.floor((buffer(offset,2):uint() % 1024 ) / 64)
    slot_subtree:add(buffer(offset,1),"MSG Seq= "        .. msg_seq)
    slot_subtree:add(buffer(offset,1),"Slot HDR1: "      .. tostring(buffer(offset,1)))
    offset = offset + 1
    local count = 0
    repeat
      count = count + 1
      slot_subtree:add(buffer(offset,2),"Slot Data Word ".. tostring(count) ..   ": "   .. tostring(buffer(offset,2)))
      offset = offset + 2
    until (count == 31)
  until ( 5 == slot_count)
  local msg_sbi_time = tostring(buffer(offset,6))
  local msg_wall_time = sbi_to_walltime(msg_sbi_time)
  subtree:add(buffer(offset,6),"CBM_SBITime: " .. os.date("!%H:%M:%S",msg_wall_time))
  offset = offset + 6  
  local msg_sbi_time = tostring(buffer(offset,6))
  local msg_wall_time = sbi_to_walltime(msg_sbi_time)
  subtree:add(buffer(offset,6),"BCUI_SBITime: " .. os.date("!%H:%M:%S",msg_wall_time))
  offset = offset + 6  
  
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(4787,cbm103_proto)