
-------------------------------------------------------
-- This is a Wireshark dissector for the iNet-X packet format
-- http://www.cwc-ae.com/custom/pdfs/White%20Paper_iNET-X_packets.pdf
-------------------------------------------------------

-- Copyright 2014 Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuid
-- https://github.com/diarmuidcwc/LuaDissectors


-- To use this dissector you need to include this file in your init.lua as follows:

-- CUSTOM_DISSECTORS = DATA_DIR.."LuaDissectors" -- Replace with the directory containing all the scripts
-- dofile(CUSTOM_DISSECTORS.."\\inetx_generic.lua")



-- Common functions. These are always needed
--dofile(CUSTOM_DISSECTORS.."\\common.lua")

-- These are some custom iNetX payloads that I want to dissect.
-- These can be commented out if not needed
--dofile(CUSTOM_DISSECTORS.."\\parser_aligned.lua")
--dofile(CUSTOM_DISSECTORS.."\\LXRS.lua")
--dofile(CUSTOM_DISSECTORS.."\\arinc_msgs.lua")
--dofile(CUSTOM_DISSECTORS.."\\ubm_msgs.lua")
--dofile(CUSTOM_DISSECTORS.."\\mpegts.lua")
--dofile(CUSTOM_DISSECTORS.."\\custom_inetx.lua")
--dofile(CUSTOM_DISSECTORS.."\\counter.lua")

-- Hook up dissectors to certain ports. You need to add these 
-- ports at the bottom if you want them automatically dissected
PARSER_ALIGNED_PORT = 8014
BCU_TEMPERATURE_PORT = 23454
MAT101_PORT = 1027
VID106_REPORT_PORT = 5523
ADC114_PORT = 5567
TCG105_PORT = 9898
TCG102_PORT = 9899
ARINCMESSAGES = 5568
VLINK_PORT = 1026

PACKAGE_GEN = 1025
VIDEO_PORT = 8011
LXRS_PORT = 5555
WSI104_ID  = 0xdc8
WSI104_ID2 = 0xdc4
WSI104_REPORT = 0xdc6
WSI104_NODE_1 = 0xdc8
WSI104_NODE_2 = 0xdc4
WSI104_NODE_32bit = 0xdc5
WSI_REPORT_PORT = 4443
DBG_SRAM_PORT = 2024
INETX_PORT = 8015
SWI101_PORT = 47562
GARINC = 9999
ABM401_PORT = 8015
PALIGNED_PORT = 5545
ETH_STATUS_PORT = 8011
ETH_STATUS_PORT2 = 8014

MBM_STREAM_ID_WITH_BLOCK = 2
MBM_STREAM_ID_WITHOUT_BLOCK = 1

    
-- trivial protocol example
-- declare our protocol
inetx_generic_proto = Proto("inetx","Generic iNetX Protocol")

-- Declare a few fields
f_inetcontrol = ProtoField.uint32("inetx.control","Control",base.HEX)
f_streamid = ProtoField.uint32("inetx.streamid","StreamID",base.HEX)
f_inetsequencenum = ProtoField.uint32("inetx.sequencenum","Sequence Number",base.DEC)
f_packetlen = ProtoField.uint32("inetx.packetlen","Packet Length",base.DEC)
f_ptpseconds = ProtoField.uint32("inetx.ptpseconds","PTP Seconds",base.DEC)
f_ptpnanoseconds = ProtoField.uint32("inetx.ptpnanoseconds","PTP Nanoseconds",base.DEC)
f_pif = ProtoField.uint32("inetx.pif","PIF",base.HEX)
f_inetxerrorbit  = ProtoField.uint32("inetx.EB", "EB", base.HEX)
f_inetxlostcount  = ProtoField.uint32("inetx.lostcout", "Lost Count", base.DEC)
f_inetxtimeout  = ProtoField.uint32("inetx.TO", "Timeout", base.HEX)

inetx_generic_proto.fields = {f_inetcontrol,f_streamid,f_inetsequencenum,f_packetlen,f_ptpseconds,f_ptpnanoseconds,f_pif, f_inetxerrorbit, f_inetxlostcount, f_inetxtimeout}

function getValue(buffer_range)
  return buffer_range: uint()
end

function do_swi101_status(tree, buffer)
    
    -- Declare a few useful variables to make the output readable
    local linkmode = {}
    linkmode[0x0] = "Autonegotiate"
    linkmode[0x1] = "Forced 10"
    linkmode[0x2] = "Forced 100"
    linkmode[0x3] = "Forced 1G"
    
    local linkspeed = {}
    linkspeed[0x0] = "Not Connected"
    linkspeed[0x1] = "10Mbps"
    linkspeed[0x2] = "100Mbps"
    linkspeed[0x3] = "1G"  
    
    local timesource = {}
    timesource[0] = "Not Synchronised"
    timesource[1] = "PTPv1 GM"
    timesource[2] = "PTPv2 GM"
    timesource[3] = "GPS"
    timesource[4] = "A-IRIG-B"
    timesource[5] = "D-IRIG-B"
    
    local fs = {}
    fs[31] = "Time Source Available"
    fs[25] = "Internal GPS"
    fs[21] = "GPS In Lock"
    fs[20] = "Time Reliable"
    fs[19] = "PTPv1GM Enabled"
    fs[18] = "PTPv2GM Enabled"
    fs[17] = "PTPv1 Client"
    fs[16] = "PTPv2 Client"
    
  
    offset = 0
    -- Split the flag status
    local flag_status = getValue(buffer(offset,4))
    for i,v in pairs(fs) do
        val = bit32.extract(flag_status,i)
        tree:add(buffer(offset,4), string.format("%s: %x", v, val))
    end 
    -- Skip the GPS bit
    offset = offset + 24
    tree:add(buffer(offset,4), "PTP Reliability Level: " .. getValue(buffer(offset,4)))
    offset = offset + 4
    -- The PTP time source
    tree:add(buffer(offset,1), "Time Source: " .. timesource[getValue(buffer(offset,1))])
    offset = offset + 12
    
    -- Loop through the ports
    port_num = 1
    repeat
    
    
        local link_status = getValue(buffer(offset,4))
        local st = {}
        
        st.active  = bit32.extract(link_status,31)
        st.halfduplex  = bit32.extract(link_status,30)
        st.fullduplex  = bit32.extract(link_status,29)
        st.linkspeed  = bit32.extract(link_status,0,4)
        st.linkmode  = bit32.extract(link_status,4,4)
        --string.format("Info Word. Empty: %x Stale: %x Skipped: %x Bus: %d", message.empty
        tree:add(buffer(offset,4), string.format("Port: %d Active: %x Half-duplex: %x Full-duplex: %x Link-mode: %s Link-speed: %s", port_num, 
        st.active, st.halfduplex, st.fullduplex, linkmode[st.linkmode], linkspeed[st.linkspeed]))
        
        -- Skip the counters
        offset = offset + 24
        port_num = port_num + 1
    until (port_num == 9)

end

function axnbcu_eth_status_dissector(buffer, pinfo, tree)
	local offset = 0
	local link_status = getValue(buffer(offset,2))
	local linkspeed = {}
    linkspeed[0x0] = "10Mbps"
    linkspeed[0x1] = "100Mbps"
    linkspeed[0x2] = "1G"  
    linkspeed[0x3] = "Illegal"  

	for p=0,1 do
		local link_down =  bit32.extract(link_status,14+p)
		--if link_down == 1 then
		--	tree:add(buffer(offset,2), string.format("Port: %d Down: %x Full-duplex: - Link-speed: -", p, 
		--	link_down))
		--else
		tree:add(buffer(offset,2), string.format("Port: %d Down: %x Full-duplex: %x Link-speed: %s", p, 
		link_down, bit32.extract(link_status,12+p), linkspeed[bit32.extract(link_status,8+2*p,2)]))
		--end
		
	end	

end

function mbm_dissector(buffer, pinfo, iNetX_top_subtree, stream_id_v)

    
    local offset = 0
    local v_len = buffer:len()
    mbmsubtree = iNetX_top_subtree:add(buffer(offset,v_len),"MBM Block")
    if (stream_id_v == MBM_STREAM_ID_WITH_BLOCK) then
        mbmsubtree:add(buffer(offset,2),"BlockID = 0x" .. buffer(offset,2))
        offset = offset + 2
    end
    local v_stream = 1
    repeat 
        local v_data_words = buffer(offset,2):uint() % 32
        if v_data_words == 0 then
            v_data_words = 32
        end
        streamtree = mbmsubtree:add(buffer(offset,(v_data_words+3) * 2),"Stream #" .. v_stream)
        streamtree:add(buffer(offset,v_data_words*2),"Command = 0x" .. buffer(offset,2))
        offset = offset + 2
        streamtree:add(buffer(offset,v_data_words*2),"Data Words ".. v_data_words)
        streamtree:add(buffer(offset,2),"Data Word Incremeter = " .. buffer(offset,2):uint())
        offset = offset + v_data_words*2
        streamtree:add(buffer(offset,2),"Status = 0x" .. buffer(offset,2))
        offset = offset + 2
        streamtree:add(buffer(offset,2),"Time = 0x" .. buffer(offset,2))
        offset = offset + 2
        v_stream = v_stream + 1
    until (offset == v_len)
    
end


-- create a function to dissect it
function inetx_generic_proto.dissector(buffer,pinfo,tree)

	--LXRS_ID = 12648430
    LXRS_ID = 0xdc1
    --LXRS_ID = 0xabcd0a9a
	
  udp_dst_f = pinfo.dst_port
  pinfo.cols.protocol = "inetx"
  local iNetX_top_subtree = tree:add(inetx_generic_proto,buffer(),"iNet-X Protocol Data")
  
  -- The iNet-X Header Definition
  
  subtree = iNetX_top_subtree:add(buffer(0,28),"iNetX Header")
  local offset=0
  
  subtree:add(f_inetcontrol,buffer(offset,4))
  offset = offset + 4
  
  subtree:add(f_streamid,buffer(offset,4))
  local stream_id_v = buffer(offset,4):uint()
  offset = offset + 4
  
  subtree:add(f_inetsequencenum,buffer(offset,4))
  offset = offset + 4
  
  subtree:add(f_packetlen,buffer(offset,4))
  local iNetX_payloadsize_in_bytes = buffer(offset,4):uint() - 28
  offset = offset + 4
  
  ptptimesubtree = subtree:add(buffer(offset,8),"PTPTimeStamp")
  --if ( buffer(offset,4):uint() > 1576800000 ) then
  --ptptimesubtree:add(buffer(offset,4),"Date: ERROR. Some time after 2020")
  --else
  ptptimesubtree:add(buffer(offset,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset,4):uint()))
  --end
  ptptimesubtree:add(f_ptpseconds,buffer(offset,4))
  offset = offset + 4
  
  ptptimesubtree:add(f_ptpnanoseconds,buffer(offset,4))
  offset = offset + 4
  
  subtree:add(f_pif,buffer(offset,4))
  pifsubtree = subtree:add(buffer(offset,4), "PIF")
  local pif_value = getValue(buffer(offset,4))
  pifsubtree:add(f_inetxerrorbit, buffer(offset,1), bit32.extract(pif_value,31))
  pifsubtree:add(f_inetxlostcount, buffer(offset,1),  bit32.extract(pif_value,27, 4))
  pifsubtree:add(f_inetxtimeout, buffer(offset,1),  bit32.extract(pif_value,26))
  
  offset = offset + 4
   
  -- iNet-X Payload
  subtree = iNetX_top_subtree:add(buffer(offset,iNetX_payloadsize_in_bytes),"iNetX Data (" .. iNetX_payloadsize_in_bytes .. ")" )

    if ( udp_dst_f == ABM401_PORT or udp_dst_f == PALIGNED_PORT) then
    
        parseraligneddissector = Dissector.get("parseraligned")
        parseraligneddissector:call(buffer(offset,iNetX_payloadsize_in_bytes):tvb(),pinfo,subtree)
        offset = offset + iNetX_payloadsize_in_bytes
    end
	
    if ( udp_dst_f >= ETH_STATUS_PORT and udp_dst_f <= ETH_STATUS_PORT2 ) then
		offset = offset + 2
        axnbcu_eth_status_dissector(buffer(offset,2):tvb(),pinfo,subtree)
        offset = offset + iNetX_payloadsize_in_bytes
    end    
    
  if ( stream_id_v >= 0xdc3 and stream_id_v <= 0xdc4 ) then
        -- DATA IN AUTOMATIC PACKETS ---
        local slot = 1
        datasubtree = subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"iNetX Analog Packetizer")        
        local error_code = (buffer(offset,1):uint())/16
        local quad_bytes = (buffer(offset,2):uint()) % 256
        datasubtree:add(buffer(offset,2),"Error Code: " .. error_code)
        datasubtree:add(buffer(offset,2),"Quad Bytes: " .. quad_bytes)
        offset = offset + 2
        datasubtree:add(buffer(offset,2),"Channel Count: " .. buffer(offset,2):uint())
        channel_count_v = buffer(offset,2):uint()
        offset = offset + 2
        datasubtree:add(buffer(offset,1),"Data Format: " .. buffer(offset,1):uint())
        local data_type_v = buffer(offset,1):uint()
        offset = offset + 2
        datasubtree:add(buffer(offset,2),"Sample count: " .. buffer(offset,2):uint())
        local sample_count_v = buffer(offset,2):uint()
        offset = offset + 2
        datasubtree:add(buffer(offset,4),"Nanosec Tick: " .. buffer(offset,4):uint())
        offset = offset + 4
        datasubtree:add(buffer(offset,2),"FracNanosec Tick: " .. buffer(offset,2):uint())
        offset = offset + 2
        offset = offset + 2
        datasubtree:add(buffer(offset,4),"Channel Mask: " .. buffer(offset,4))
        offset = offset + 4

        local parser_byte_count = 20 -- already have read 3 quad bytes
        local sample = 0
        local ch_num = 0
        local word_size = 2
        if ( data_type_v == 2 or data_type_v == 4 or data_type_v == 8 ) then
            word_size = 4
        elseif ( data_type_v == 9 or data_type_v == 11 ) then
            word_size = 3
        end        
        repeat  -- sample repeat
            lxrs_subtree = datasubtree:add(buffer(offset,word_size*channel_count_v),"Sweep " .. sample+1)
            repeat -- channel repeat
                --local pdetail = parse_arinc_detail(buffer(offset,1):uint(),buffer(offset+1,1):uint(),buffer(offset+2,1):uint(),buffer(offset+3,1):uint())
                --slotsubtree:add(buffer(offset,4),pdetail)
                lxrs_subtree:add(buffer(offset,word_size),"Channel #" .. ch_num+1 .." : " .. buffer(offset,word_size))
                ch_num = ch_num + 1
                offset = offset + word_size
                parser_byte_count = parser_byte_count + word_size
            until (ch_num == channel_count_v)
            sample = sample + 1
            ch_num = 0
        until (sample == sample_count_v)
        v_padding = quad_bytes*4-parser_byte_count
        if v_padding > 0 then
            datasubtree:add(buffer(offset,v_padding),"Padding " .." : " .. buffer(offset,v_padding))
            offset = offset + v_padding
        end 
  end
  
  
  -- sample dissector for VID 106 payload
  if ( pinfo.dst_port == VIDEO_PORT ) then
     pinfo.cols.protocol = "VID106"
     fastmode = false
      -- DATA IN VIDEO PACKETS ---
      local slot = 1
      datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"iNetX Payload (VID)")
      repeat 
        syncword = tostring(buffer(offset,3))
        if ( syncword == "470100" or  syncword == "470101" or syncword == "474100" or syncword == "474101" or syncword == "471FFF" or syncword == "474000" or syncword == "475000"  ) then
            insync = "In Sync"
        else
            insync = "Out of Sync"
        end
		mpegtsdissector = Dissector.get("mpegts")
		block_tree = datasubtree:add(buffer(offset,188),"MPEG Block "..slot)
		mpegtsdissector:call(buffer(offset,188):tvb(),pinfo,block_tree)
        offset = offset + 188
        slot = slot + 1
      until (offset == iNetX_payloadsize_in_bytes+28)
  end
  
	

	-- payload contains a customer dissector. Call it here
	if(pinfo.src_port == SWI101_PORT) then
		do_swi101_status(subtree, buffer(offset,232))
	end			
	


	if(pinfo.dst_port == DBG_SRAM_PORT) then
		dbgtree =  subtree:add(buffer(offset,20),"AXON Check")
		dbgtree:add(buffer(offset,2),"RX Frame Count = " .. buffer(offset,2):uint())
		offset = offset + 2
		dbgtree:add(buffer(offset,2),"RX Err Count = " .. buffer(offset,2):uint())
		offset = offset + 2
		
		--dbgtree:add(buffer(offset,4),"SRAM Errors = " .. buffer(offset,4):uint())
		--offset = offset + 4
		dbgtree:add(buffer(offset,4),"SRAM Checks = " .. buffer(offset,4):uint())
		offset = offset + 6
		dbgtree:add(buffer(offset,12),"Address    = 0x" .. buffer(offset+4,8):uint64():tohex())
		offset = offset + 12
		dbgtree:add(buffer(offset+3,1),  "Data Write #2 = " .. string.format("0x%02x_%08x", 
				bit32.rshift(buffer(offset+3,1):uint(),4),bit32.lshift(buffer(offset+3,4):uint(),4)+bit32.rshift(buffer(offset+7,1):uint(),4)))
		dbgtree:add(buffer(offset+7,5),  "Data Write #1 = " .. string.format("0x%02x_%08x",
				bit32.band(buffer(offset+7,1):uint(),0xf),buffer(offset+8,4):uint()))
		--dbgtree:add(buffer(offset,12),"Data Write = 0x" .. buffer(offset,4).."_"..buffer(offset+4,4).."_"..buffer(offset+8,4))
		offset = offset + 12
		dbgtree:add(buffer(offset+3,5),  "Data Read  #2 = " .. string.format("0x%02x_%08x", 
				bit32.rshift(buffer(offset+3,1):uint(),4),bit32.lshift(buffer(offset+3,4):uint(),4)+bit32.rshift(buffer(offset+7,1):uint(),4)))
		dbgtree:add(buffer(offset+7,5),  "Data Read  #1 = " .. string.format("0x%02x_%08x",
				bit32.band(buffer(offset+7,1):uint(),0xf),buffer(offset+8,4):uint()))
		--dbgtree:add(buffer(offset,12),"Data Read  = 0x" .. buffer(offset,4).."_"..buffer(offset+4,4).."_"..buffer(offset+8,4))
		offset = offset + 12
		dbgtree:add(buffer(offset,2),"PLL Loss Lock = " .. buffer(offset,2):uint())
		offset = offset + 4
		dbgtree:add(buffer(offset,1),"Fifo Fill Cnt = " .. buffer(offset,1):uint())
	end	
	
		
	-- Example of a dissector which depends on the length of a packet
	if(pinfo.len == 1199 or pinfo.len == 1198) then
	
		-- Hook the BCU dissector onto this depending on the size

		if (stream_id_v == 0x13) then
			dau = 0
		elseif (stream_id_v == 0x22) then
			dau = 1
		elseif (stream_id_v == 0x32) then
			dau = 2
		elseif (stream_id_v == 0x42) then
			dau = 3
		elseif (stream_id_v == 0x2) then
			dau = "m"
		else 
			dau = "unknown"
		end
		
		-- 
		local buf_size = 22
		if(pinfo.len == 98) then
			buf_size = 28
		end
		subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"Dau "..dau.." Status")
		bcu_dissector = Dissector.get("bcureport")
		bcu_dissector:call(buffer(offset,buf_size):tvb(),pinfo,subtree)
	end
	

	-- payload contains a customer dissector. Call it here
 	-- if(pinfo.dst_port == MAT101_PORT) then
		-- psstree = subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"PSS Counters")
		-- psstree:add(buffer(offset,2),"RX Packet Count=  " .. buffer(offset,2):uint())
		-- offset = offset + 2
		-- psstree:add(buffer(offset,2),"RX DV Count=      " .. buffer(offset,2):uint())
		-- offset = offset + 2
		-- psstree:add(buffer(offset,2),"RX ER Count=      " .. buffer(offset,2):uint())
		-- offset = offset + 2
		-- psstree:add(buffer(offset,2),"RX Preamble Count=" .. buffer(offset,2):uint())
	-- end   

    -- WSI 104 debug
	-- payload contains a n LXRS packet
	if(pinfo.dst_port == LXRS_PORT) then
        if (stream_id_v == LXRS_ID) then
            pinfo.cols.protocol = "LXRS"	
            lxrs_dissector = Dissector.get("lxrs")
            lxrs_dissector:call(buffer(offset,iNetX_payloadsize_in_bytes):tvb(),pinfo,subtree)
        elseif (stream_id_v == WSI104_NODE_1 or stream_id_v == WSI104_NODE_2) then
            pinfo.cols.protocol = "WSI104_node"
            datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"Node Data")
            local active_channels = 1
            local channel = 1 
            local sweep_count = 1
            repeat
                local sweep_tree =  datasubtree:add(buffer(offset,2*active_channels),"Pattern " .. sweep_count)
                local ch = 1
                repeat
                    sweep_tree:add(buffer(offset,2),"Channel: " .. ch .. " = " .. buffer(offset,2):uint())
                    offset = offset + 2
                    ch = ch + 1
                until (ch == active_channels+1)
                sweep_count = sweep_count + 1
            until (offset == iNetX_payloadsize_in_bytes+28)
        elseif (stream_id_v == WSI104_NODE_32bit) then
            pinfo.cols.protocol = "WSI104_32b"
            datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"Node Data")
            local active_channels = 2
            local channel = 1 
            local sweep_count = 1
            repeat
                local sweep_tree =  datasubtree:add(buffer(offset,4*active_channels),"Pattern " .. sweep_count)
                local ch = 1
                repeat
                    sweep_tree:add(buffer(offset,4),"Channel: " .. ch .. " = " .. buffer(offset,4):uint())
                    offset = offset + 4
                    ch = ch + 1
                until (ch == active_channels+1)
                sweep_count = sweep_count + 1
            until (offset == iNetX_payloadsize_in_bytes+28)
        
        end
	end		
    
    
    if (pinfo.dst_port == PACKAGE_GEN) then
        counter_dissector = Dissector.get("counter")
		counter_dissector:call(buffer(offset,iNetX_payloadsize_in_bytes):tvb(),pinfo,subtree)
    end 
    
    if (pinfo.dst_port == ARINCMESSAGES) then
    
        dofile(CUSTOM_DISSECTORS.."\\abm401.lua")
        msg_count = 0
        repeat
            local msg_tree = iNetX_top_subtree:add(buffer(offset,4),"ARINC: " .. msg_count)
            axon_abm401_messagedatastyleA(msg_tree, buffer(offset,4))
            offset = offset + 4
            msg_count = msg_count + 1
        until (offset == iNetX_payloadsize_in_bytes+28)
    end  

    if (stream_id_v == MBM_STREAM_ID_WITH_BLOCK or stream_id_v == MBM_STREAM_ID_WITHOUT_BLOCK) then
        mbm_dissector(buffer(offset) , pinfo, iNetX_top_subtree, stream_id_v)
    end
	
	if (stream_id_v == 0x2f) then
		datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"Data")
		datasubtree:add(buffer(offset,2), string.format("Report = %x",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("TXNodeAddr#1 = %d",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("TXNodeRSSI#1 = %x",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("TXNodeAddr#2 = %d",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("TXNodeRSSI#2 = %x",buffer(offset,2):uint()))
		offset = offset + 2
		channel = 0
		repeat
			datasubtree:add(buffer(offset,2), string.format("Channel %d = %x (%d)",channel, buffer(offset,2):uint(), buffer(offset,2):uint()))
			offset = offset + 2
			channel = channel + 1
		until (offset == iNetX_payloadsize_in_bytes+28)
	end
 
	if (stream_id_v == 0xb01) then
		datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"MBM Parser")
		
		local channel = 0
		repeat
			chtree = datasubtree:add(buffer(offset, 5), string.format("Channel %d", channel))
			chtree:add(buffer(offset,2), string.format("Message Count = %d", buffer(offset,2):uint()))
			offset = offset + 2
			local wall_time = sbi_to_walltime(tostring(buffer(offset,6)))
            chtree:add(buffer(offset,6),"SBI Time (ptp equivalent): " .. os.date("%H:%M:%S %d %b",wall_time))
            local usec = string.sub(tostring(buffer(offset,6)),-6)
            chtree:add(buffer(offset,6),"useconds: " .. usec)
			offset = offset + 6
			chtree:add(buffer(offset,2), string.format("Message Payload = %#0X", buffer(offset,2):uint()))
			offset = offset + 2
			channel = channel + 1
		until (offset == iNetX_payloadsize_in_bytes+28)
	end
	if (stream_id_v == 0xb02) then
		datasubtree = iNetX_top_subtree:add(buffer(offset,iNetX_payloadsize_in_bytes),"MBM Status")
		datasubtree:add(buffer(offset,2), string.format("Bus Active = %#0x",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("Report = %#0x",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("MsgCount = %d",buffer(offset,2):uint()))
		offset = offset + 2
    end 
    if pinfo.dst_port == GARINC then
        arincdissector = Dissector.get("arinc429")
        ch_count = 0
        repeat 
            local ch_tree = iNetX_top_subtree:add(buffer(offset,12),"G-ARINC: " .. ch_count)
            arincdissector:call(buffer(offset,4):tvb(),pinfo,ch_tree)
            offset = offset + 4
            ch_tree:add(buffer(offset,2),"Message Count: " .. buffer(offset,2):uint())
            offset = offset + 2
            local wall_time = sbi_to_walltime(tostring(buffer(offset,6)))
            ch_tree:add(buffer(offset,6),"SBI Time (ptp equivalent): " .. os.date("%H:%M:%S %d %b",wall_time))
            local usec = string.sub(tostring(buffer(offset,6)),-6)
            ch_tree:add(buffer(offset,6),"useconds: " .. usec)
           offset = offset + 6
            ch_count = ch_count + 1
        until offset == iNetX_payloadsize_in_bytes+28
    
    end
	
	if pinfo.dst_port == VLINK_PORT then
		offset = 50
        local vlink_data = iNetX_top_subtree:add(buffer(offset,8),"Vlink-_ch6 ")
		repeat
			vlink_data:add(buffer(offset,2),  string.format("Data = %#0x",buffer(offset,2):uint()))
			offset = offset + 2
		until offset == 58
	end
	
	if (pinfo.dst_port == 9) then
		datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"MEM401Dbg")
		offset = offset + 2 
		datasubtree:add(buffer(offset,2), string.format("IQ_Drop_0 = %d",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("IQ_Drop_1 = %d",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("IQ_Count_0 = %d",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("IQ_Count_1 = %d",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("IQ_FillCount_0 = %d",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("IQ_FillCount_1 = %d",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("OQ_DiscardCount_0 = %d",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("OQ_DiscardCount_1 = %d",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("PauseEn = %x",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,2), string.format("ErrCnt = %d",buffer(offset,2):uint()))
		offset = offset + 2
		datasubtree:add(buffer(offset,4), string.format("PacketCount = %d",buffer(offset,4):uint()))
		offset = offset + 4
		datasubtree:add(buffer(offset,4), string.format("PacketTS = %d",buffer(offset,4):uint()))
		offset = offset + 4
		datasubtree:add(buffer(offset,4), string.format("OutputBridgeCount = %d",buffer(offset,4):uint()))
	end
    
end

-- This is where you can hook up ports automatically
-- So for instance if you want the inetx dissector automatically
-- run on the VIDEO_PORT

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port VIDEO_PORT
udp_table:add(PARSER_ALIGNED_PORT,inetx_generic_proto)
udp_table:add(PALIGNED_PORT,inetx_generic_proto)
udp_table:add(ADC114_PORT,inetx_generic_proto)
udp_table:add(VIDEO_PORT,inetx_generic_proto)
udp_table:add(INETX_PORT,inetx_generic_proto)
udp_table:add(LXRS_PORT,inetx_generic_proto)
udp_table:add(WSI_REPORT_PORT,inetx_generic_proto)
udp_table:add(ARINCMESSAGES,inetx_generic_proto)
udp_table:add(VLINK_PORT,inetx_generic_proto)
--udp_table:add(ETH_STATUS_PORT,inetx_generic_proto)
--udp_table:add(ETH_STATUS_PORT+1,inetx_generic_proto)
--udp_table:add(ETH_STATUS_PORT+2,inetx_generic_proto)
--udp_table:add(ETH_STATUS_PORT+3,inetx_generic_proto)
--udp_table:add(ETH_STATUS_PORT+4,inetx_generic_proto)

--udp_table:add(PACKAGE_GEN,inetx_generic_proto)

