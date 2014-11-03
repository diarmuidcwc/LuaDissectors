dofile("common.lua")

-- trivial protocol example
-- declare our protocol
ssr_upd_test_proto = Proto("ssr_upd_test","SSR CHS ")
-- create a function to dissect it
function ssr_upd_test_proto.dissector(buffer,pinfo,tree)
  pinfo.cols.protocol = "ssr_upd_test" -- the name in the wirshark view
  udp_dst_f = pinfo.dst_port

  if ( udp_dst_f == 9191 ) then
    local iena_top_subtree = tree:add(ssr_upd_test_proto,buffer(),"SSR IENA Protocol Data")
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
    local bcu_sbi_time = tostring(buffer(offset,6))
    local bcu_wall_time = sbi_to_walltime(bcu_sbi_time)
    subtree:add(buffer(offset,6),"BCU_SBITime: " .. os.date("!%H:%M:%S",bcu_wall_time))
    offset = offset + 6
    subtree:add(buffer(offset,2),"BCU_TIME_DAYOFYEAR: " .. buffer(offset,2):uint())
    offset = offset + 2
    subtree:add(buffer(offset,4),"J2_RX_FRM_COUNT: " .. buffer(offset,4):uint())
    offset = offset + 4
    subtree:add(buffer(offset,2),"TCG102C_DOY: " .. buffer(offset,2):uint())
    offset = offset + 2
    local tcg_sbi_time = tostring(buffer(offset,6))
    local tcg_wall_time = sbi_to_walltime(tcg_sbi_time)
    subtree:add(buffer(offset,6),"TCG_SBITime: " .. os.date("!%H:%M:%S",tcg_wall_time))
    offset = offset + 6
    subtree:add(buffer(offset,2),"TCG102C_GPS_STATUS: " .. buffer(offset,2):uint())
    offset = offset + 2
    subtree:add(buffer(offset,2),"TCG102C_SBS: " .. buffer(offset,2):uint())
    offset = offset + 2
    subtree:add(buffer(offset,2),"TCG102C_LATHI: " .. buffer(offset,2):uint())
    offset = offset + 2
    subtree:add(buffer(offset,2),"TCG102C_LATLO: " .. buffer(offset,2):uint())
    offset = offset + 2
    subtree:add(buffer(offset,2),"TCG102C_LATMI: " .. buffer(offset,2):uint())
    offset = offset + 2
    subtree:add(buffer(offset,2),"TCG102C_LONHI: " .. buffer(offset,2):uint())
    offset = offset + 2
    subtree:add(buffer(offset,2),"TCG102C_PTPDAYS: " .. buffer(offset,2):uint())
    offset = offset + 2
    subtree:add(buffer(offset,2),"TCG102C_LONLO: " .. buffer(offset,2):uint())
    offset = offset + 2
    local cbm_sbi_time = tostring(buffer(offset,6))
    local cbm_wall_time = sbi_to_walltime(cbm_sbi_time)
    subtree:add(buffer(offset,6),"CBM_SBITime: " .. os.date("!%H:%M:%S",cbm_wall_time))
    offset = offset + 6
    subtree:add(buffer(offset,2),"CBM_Report: " .. buffer(offset,2):uint())
    offset = offset + 2
    subtree:add(buffer(offset,2),"CBM_RdCounter: " .. buffer(offset,2):uint())
    offset = offset + 2
   
  elseif (udp_dst_f == 8181 or udp_dst_f == 4027  or udp_dst_f == 9191) then
  
    local xnet_top_subtree = tree:add(ssr_upd_test_proto,buffer(),"xNet BCU") 
    if ( udp_dst_f == 8181 ) then
      xnet_top_subtree:add(buffer(offset,0),"VDS Automatic Packets" )   
    elseif ( udp_dst_f == 9191 ) then
      xnet_top_subtree:add(buffer(offset,0),"PBM104 Automatic Packets" )   
    else
      xnet_top_subtree:add(buffer(offset,0),"ABM Automatic Packets" )   
    end
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
  -- DATA IN AUTOMATIC PACKETS BCU ---
    local slot = 1
    datasubtree = xnet_top_subtree:add(buffer(offset,(xnet_payloadsize_in_bytes)),"xNet Payload (BCU) (Automatic)")
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
        slotsubtree:add(buffer(offset,4),"Message Data: " .. buffer(offset,4):uint())
        offset = offset + 4
        quad_count = quad_count + 1
      until (quad_count == quad_bytes-2)
      slot = slot + 1
    until (offset == xnet_payloadsize_in_bytes+28)  
  end
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(1616,ssr_upd_test_proto)