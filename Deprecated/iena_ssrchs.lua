dofile("common.lua")

-- trivial protocol example
-- declare our protocol
iena_ssrchs_proto = Proto("iena_ssrchs","IENA SSRCHS Protocol")
-- create a function to dissect it
function iena_ssrchs_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "iena_ssrchs" -- the name in the wirshark view
    local iena_top_subtree = tree:add(iena_ssrchs_proto,buffer(),"IENA Protocol Data")
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
  local ip_address = format_ip(tostring(buffer(offset,4)))
  datasubtree:add(buffer(offset,4),"ETH102_IP_ADD: " .. ip_address)
  offset = offset + 4
  local mac_address = format_mac_address(tostring(buffer(offset,6)))
  datasubtree:add(buffer(offset,6),"ETH102_MAC_ADDR: " .. mac_address)
  offset = offset + 6
  datasubtree:add(buffer(offset,2),"ETH102_RX_FRAME_COUNT_0_L: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"ETH102_RX_FRAME_COUNT_0_U: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"ETH102_ERROR_COUNT_0: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"ETH102_DROP_COUNT_0: " .. buffer(offset,2):uint())
  offset = offset + 2
  datasubtree:add(buffer(offset,2),"ETH102_PTP_DAYS: " .. buffer(offset,2):uint())
  offset = offset + 2
  local bcu_sbi_time = tostring(buffer(offset,6))
  local bcu_wall_time = sbi_to_walltime(bcu_sbi_time)
  datasubtree:add(buffer(offset,6),"BCU_SBITime: " .. os.date("!%H:%M:%S",bcu_wall_time))
  offset = offset + 6
  datasubtree:add(buffer(offset,2),"BCU_TIME_DAYOFYEAR: " .. buffer(offset,2):uint())
  offset = offset + 2
	end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(3101,iena_ssrchs_proto)