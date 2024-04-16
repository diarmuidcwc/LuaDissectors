

PARSER_ALIGNED_PORT = 8014
BCU_TEMPERATURE_PORT = 23454
MAT101_PORT = 1027
VID106_REPORT_PORT = 5523
ADC114_PORT = 1
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
----------------------------
-- MBM over iNetX  
---------------------------
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


----------------------------
-- MPEG TS OVER iNetX  
---------------------------
mpegts_payload_proto = Proto("vidpayload", "Video Protocol")

function mpegts_payload_proto.dissector(buffer, pinfo, tree)

    -- sample dissector for VID 106 payload
    pinfo.cols.protocol = "video over inetx"
    local buf_len = buffer:len()
    -- DATA IN VIDEO PACKETS ---
    local slot = 1
    local offset = 0
    local datasubtree = tree:add(buffer(offset,(buf_len)),"VID Payload")
    repeat 
        local syncword = tostring(buffer(offset,3))
        if ( syncword == "470100" or  syncword == "470101" or syncword == "474100" or syncword == "474101" or syncword == "471FFF" or syncword == "474000" or syncword == "475000"  ) then
            insync = "In Sync"
        else
            insync = "Out of Sync"
        end
        local mpegtsdissector = Dissector.get("mpegts")
        local block_tree = datasubtree:add(buffer(offset,188),"MPEG Block "..slot)
        mpegtsdissector:call(buffer(offset,188):tvb(),pinfo,block_tree)
        offset = offset + 188
        slot = slot + 1
    until (offset == buf_len)
end
local function mpeg_ts_heuristic_checker(buffer, pinfo, tree)
    -- guard for length
    local length = buffer:len()
    if length < 188 then return false end

    local syncword = buffer(0,1):uint()

    if syncword == 0x47
    then
        mpegts_payload_proto.dissector(buffer, pinfo, tree)
        return true
    else return false end
end
mpegts_payload_proto:register_heuristic("inetx.payload", mpeg_ts_heuristic_checker)

----------------------------
-- WSI dissector
---------------------------
function wsi_dissector(buffer, pinfo, iNetX_top_subtree, stream_id_v)

    LXRS_PORT = 5555
    WSI104_ID  = 0xdc8
    WSI104_ID2 = 0xdc4
    WSI104_REPORT = 0xdc6
    local WSI104_NODE_1 = 0xdc8
    local WSI104_NODE_2 = 0xdc4
    local WSI104_NODE_32bit = 0xdc5

    -- WSI 104 debug
    -- payload contains a n LXRS packet
    local buf_len = buffer:len()
    local offset = 0
    if (stream_id_v == LXRS_ID) then
        pinfo.cols.protocol = "LXRS"	
        lxrs_dissector = Dissector.get("lxrs")
        lxrs_dissector:call(buffer(offset,buf_len):tvb(),pinfo,subtree)
    elseif (stream_id_v == WSI104_NODE_1 or stream_id_v == WSI104_NODE_2) then
        pinfo.cols.protocol = "WSI104_node"
        datasubtree = iNetX_top_subtree:add(buffer(offset,buf_len),"Node Data")
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
        datasubtree = iNetX_top_subtree:add(buffer(offset,buf_len),"Node Data")
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
        until (offset == buf_len)
    
    end
end
--function mpegts_payload_proto.init()
--   inetx_table = DissectorTable.get("inetx.payload")
--    inetx_table:add(0xa00, mpegts_payload_proto)
--end
