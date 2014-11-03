dofile("common.lua")
-- trivial protocol example
-- declare our protocol
iena_cbm_proto = Proto("iena_cbm","IENA CBM104 Protocol")
-- create a function to dissect it
function iena_cbm_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "iena_cbm" -- the name in the wirshark view
    local iena_top_subtree = tree:add(iena_cbm_proto,buffer(),"IENA Protocol Data")
  -- create a subtree for the IENA Header
	subtree = iena_top_subtree:add(buffer(0,13),"IENA Header")
  local offset=0
	subtree:add(buffer(offset,2),"IENA Key: " .. tostring(buffer(offset,2)))
  offset = offset + 2
	subtree:add(buffer(offset,2),"Size: " .. buffer(offset,2):uint())
  offset = offset + 2
	local iena_size_in_words = buffer(2,2):uint()
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
  datasubtree = iena_top_subtree:add(buffer(14,(iena_size_in_words*2-16)),"Data")
  datasubtree:add(buffer(offset,2),"CBM_RdCounter: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"ETH102_REPORT: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"ETH102_MODE: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"ETH102_LINK_STATUS: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"ETH102_PROGRAMMING_MODE: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"ETH102_PHY_STATUS0: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  datasubtree:add(buffer(offset,1),"ETH102_IP_ADD: " .. buffer(offset,1):uint())
  offset = offset + 1
  datasubtree:add(buffer(offset,1),"ETH102_IP_ADD: " .. buffer(offset,1):uint())
  offset = offset + 1
  datasubtree:add(buffer(offset,1),"ETH102_IP_ADD: " .. buffer(offset,1):uint())
  offset = offset + 1
  datasubtree:add(buffer(offset,1),"ETH102_IP_ADD: " .. buffer(offset,1):uint())
  offset = offset + 1
  datasubtree:add(buffer(offset,1),"ETH102_MAC_ADDR: " .. tostring(buffer(offset,1)))
  offset = offset + 1
  datasubtree:add(buffer(offset,1),"ETH102_MAC_ADDR: " .. tostring(buffer(offset,1)))
  offset = offset + 1
  datasubtree:add(buffer(offset,1),"ETH102_MAC_ADDR: " .. tostring(buffer(offset,1)))
  offset = offset + 1
  datasubtree:add(buffer(offset,1),"ETH102_MAC_ADDR: " .. tostring(buffer(offset,1)))
  offset = offset + 1
  datasubtree:add(buffer(offset,1),"ETH102_MAC_ADDR: " .. tostring(buffer(offset,1)))
  offset = offset + 1
  datasubtree:add(buffer(offset,1),"ETH102_MAC_ADDR: " .. tostring(buffer(offset,1)))
  offset = offset + 1
  datasubtree:add(buffer(offset,2),"ETH101_FIRMWARE_REV_NUM: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"txe1MsgInfo: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  local sbi_time = tostring(buffer(offset,6))
  local wall_time = sbi_to_walltime(sbi_time)
  datasubtree:add(buffer(offset,6),"txe1MsgSBITime: " .. os.date("!%H:%M:%S",wall_time))
  
  datasubtree:add(buffer(offset,2),"txe1MsgTimeHi: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"txe1MsgTimeLo: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"txe1MsgTimeMicro: " .. tostring(buffer(offset,2)))
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"txe1MsgCounter: " .. buffer(offset,2):uint())
  offset = offset + 2
  local bcu_sbi_time = tostring(buffer(offset,6))
  local bcu_wall_time = sbi_to_walltime(bcu_sbi_time)
  datasubtree:add(buffer(offset,6),"BCU_SBITime: " .. os.date("!%H:%M:%S",bcu_wall_time))
  offset = offset + 6
  datasubtree:add(buffer(offset,2),"BCU_TIME_DAYOFYEAR: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,4),"ETH102_RX_FRAME_COUNT_0: " .. buffer(offset,4):uint())
  offset = offset + 4
  datasubtree:add(buffer(offset,2),"ETH102_ERROR_COUNT_0: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"ETH102_DROP_COUNT_0: " .. buffer(offset,2):uint())
  offset = offset + 2
  local eth_time = tostring(buffer(offset,6))
  local eth_wall_time = sbi_to_walltime(eth_time)
  datasubtree:add(buffer(offset,6),"ETH102_SBITime: " .. os.date("!%H:%M:%S",eth_wall_time))
  offset = offset + 6  
	end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(2034,iena_cbm_proto)
