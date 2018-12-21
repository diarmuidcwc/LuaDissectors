-------------------------------------------------------
-- This is a Wireshark dissector for the LXRS(TM) Packet format
-- http://files.microstrain.com/Wireless-Sensor-Networks-LXRS-Data-Communication-Protocol.pdf
-------------------------------------------------------

-- Copyright 2014 Diarmuid Collins dcollins@curtisswright.com

-- To use this dissector you need to include this file in your init.lua as follows:

-- CUSTOM_DISSECTORS = DATA_DIR.."LuaDissectors" -- Replace with the directory containing all the scripts
-- dofile(CUSTOM_DISSECTORS.."\\lsrx.lua")

lxrs_proto = Proto("lxrs","LXRS Protocol")

LXRS_UDP_PORT = 5000
-- Declare a few fields that we are in
f_sop = ProtoField.uint8("lxrs.sop","Start Of Packet",base.HEX)
f_dsf = ProtoField.uint8("lxrs.dsf","Delivery Stop Flag",base.HEX)
f_adt = ProtoField.uint8("lxrs.adt","App Data Type",base.HEX)
f_version = ProtoField.uint8("lxrs.sspversion","SSP Version",base.DEC)
f_naddr = ProtoField.uint16("lxrs.naddr","NodeAddress",base.DEC)
f_len= ProtoField.uint8("lxrs.len","Payload Length",base.DEC)
f_sample_mode = ProtoField.uint8("lxrs.samplemode","Sample Mode",base.DEC)
f_ch_mask = ProtoField.uint8("lxrs.channelmask","Channel Mask",base.HEX)
f_sample_rate = ProtoField.uint8("lxrs.samplerate","Sample Rate",base.DEC)
f_data_type = ProtoField.uint8("lxrs.datatype","Data Type",base.DEC)
f_sweep_tick = ProtoField.uint16("lxrs.sweeptick","Sweep Tick",base.DEC)
f_utc_sec = ProtoField.uint32("lxrs.seconds","UTC Seconds",base.DEC)
f_utc_nsec = ProtoField.uint32("lxrs.nanoseconds","UTC NanoSeconds",base.DEC)


lxrs_proto.fields = {f_sop,f_dsf,f_adt,f_version,f_naddr,f_len,f_sample_mode,f_ch_mask,f_sample_rate,f_data_type,f_sweep_tick,f_utc_sec,f_utc_nsec}

-- create a function to dissect it
function lxrs_proto.dissector(buffer,pinfo,tree)

	pinfo.cols.protocol = "lxrs"
	
	
	local datasubtree = tree:add(lxrs_proto,buffer(),"LXRS")
	local packet_tree =  datasubtree:add(buffer(offset,6),"PacketHeader")
	local offset=0
    local packet_type=0  -- 1/2 == SSP 3= TS 4=ANOTHER
	packet_tree:add(f_sop,buffer(offset,1))
	offset = offset + 1
	packet_tree:add(f_dsf,buffer(offset,1))
	offset = offset + 1
	packet_tree:add(f_adt,buffer(offset,1))
    local adt = buffer(offset,1):int()
    if adt == 0xa then
        packet_tree:add(f_version,buffer(offset,1),1)
        packet_type = 1
    elseif adt == 0x1a then
        packet_tree:add(f_version,buffer(offset,1),2)
        packet_type = 2
    elseif adt == 0x31 or adt == 0x30 then
        packet_type = 3
        --packet_tree:add(f_version,buffer(offset,1),0)
    else
        packet_type = 4
        --packet_tree:add(f_version,buffer(offset,1),0)
    end
	offset = offset + 1
	packet_tree:add(f_naddr,buffer(offset,2))
	offset = offset + 2
	packet_tree:add(f_len,buffer(offset,1))
	local payload_len = buffer(offset,1):int()
	offset = offset + 1
    
    
    if packet_type == 4 then
        local payload =  datasubtree:add(buffer(offset,payload_len),"Payload")
        offset = offset + payload_len
    elseif packet_type == 3 then
        local ts_tree =  datasubtree:add(buffer(offset,payload_len),"TimeStamp")
        ts_tree:add(buffer(offset,2),"Command ID: " .. buffer(offset,2))
        offset = offset + 2
        ts_tree:add(buffer(offset,4),"Seconds: " .. buffer(offset,4):uint())
        ts_tree:add(buffer(offset,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset,4):uint()))
        offset = offset + 4
        if adt == 0x31 then
            ts_tree:add(buffer(offset,2),"Reply Data: " .. buffer(offset,2))
            offset = offset + 2   
        end
    else
        local channel_tree =  datasubtree:add(buffer(offset,14),"ChannelHeader")

        
        -- support for both v1 and v2
        mask_len = 2
        if packet_type == 1 then
            channel_tree:add(f_sample_mode,buffer(offset,1))
            offset = offset + 1
            mask_len = 1
        end
        channel_tree:add(f_ch_mask,buffer(offset,mask_len))
        channel_mask_bit =  buffer(offset,mask_len):uint()
        local active_channel_cnt  = 0 -- this could be automatically calculated from the channel mask
        local active_channels = {}
        for bit=0,15 do
            local ch_enabled = tonumber(bit32.extract(channel_mask_bit,bit,1))
            active_channel_cnt = active_channel_cnt + ch_enabled
            if ch_enabled == 1 then
                active_channels[bit] = 1
            end
        end
        
        --table.sort(active_channels)
        offset = offset + mask_len
        channel_tree:add(f_sample_rate,buffer(offset,1))
        offset = offset + 1
        local datatype = buffer(offset,1):uint()
        if packet_type == 2 then
            datatype = buffer(offset,1):uint() % 16
            samplemode = math.floor(buffer(offset,1):uint() /16)
            channel_tree:add(f_sample_mode,buffer(offset,1),samplemode)
        end 
        channel_tree:add(f_data_type,buffer(offset,1),datatype)
        if datatype == 2 or  datatype == 4 or  datatype == 8 then
            samples_size = 4
        elseif datatype == 9 or  datatype == 11 then
            samples_size = 3
        else
            samples_size = 2
        end
        offset = offset + 1
        channel_tree:add(f_sweep_tick,buffer(offset,2))
        offset = offset + 2
        channel_tree:add(f_utc_sec,buffer(offset,4))
        channel_tree:add(buffer(offset,4), "Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset,4):uint()))
        offset = offset + 4
        channel_tree:add(f_utc_nsec,buffer(offset,4))
        offset = offset + 4
        --ptptimesubtree:add(buffer(offset,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset,4):uint()))
        local sample_tree =  channel_tree:add(buffer(offset,payload_len-14),"Samples")
        local sweep_count = 1
        repeat	
            local sweep_tree =  sample_tree:add(buffer(offset,samples_size*active_channel_cnt),"Sweep " .. sweep_count)
            for i,t in pairs(active_channels) do
                sweep_tree:add(buffer(offset,samples_size),"Channel: " .. i .. " = 0x" .. buffer(offset,samples_size) .. " ("..buffer(offset,samples_size):uint()..")")
                offset = offset + samples_size
            end
            sweep_count = sweep_count + 1
        until (offset == payload_len+6)
        datasubtree:add(buffer(offset,1),"Node RSSI: = " .. buffer(offset,1):uint())
        offset = offset + 1
        datasubtree:add(buffer(offset,1),"Base RSSI: = " .. buffer(offset,1):uint())
        offset = offset + 1
    end
    datasubtree:add(buffer(offset,2),"Checksum: = " .. buffer(offset,2):uint())
    offset = offset + 2
end


-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
udp_table:add(LXRS_UDP_PORT,lxrs_proto)
