-------------------------------------------------------
-- This is a Wireshark dissector for the LXRS(TM) Packet format
-- http://files.microstrain.com/Wireless-Sensor-Networks-LXRS-Data-Communication-Protocol.pdf
-------------------------------------------------------

-- Copyright 2014 Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuid
-- https://github.com/diarmuidcwc/LuaDissectors


-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

-- To use this dissector you need to include this file in your init.lua as follows:

-- CUSTOM_DISSECTORS = DATA_DIR.."LuaDissectors" -- Replace with the directory containing all the scripts
-- dofile(CUSTOM_DISSECTORS.."\\lsrx.lua")

lxrs_proto = Proto("lxrs","LXRS Protocol")

LXRS_UDP_PORT = 5000
-- Declare a few fields that we are in
f_sop = ProtoField.uint8("lxrs.sop","Start Of Packet",base.HEX)
f_dsf = ProtoField.uint8("lxrs.dsf","Delivery Stop Flag",base.HEX)
f_adt = ProtoField.uint8("lxrs.adt","App Data Type",base.HEX)
f_naddr = ProtoField.uint16("lxrs.naddr","NodeAddress",base.DEC)
f_len= ProtoField.uint8("lxrs.len","Payload Length",base.DEC)
f_sample_mode = ProtoField.uint8("lxrs.samplemode","Sample Mode",base.DEC)
f_ch_mask = ProtoField.uint8("lxrs.channelmask","Channel Mask",base.HEX)
f_sample_rate = ProtoField.uint8("lxrs.samplerate","Sample Rate",base.DEC)
f_data_type = ProtoField.uint8("lxrs.datatype","Data Type",base.DEC)
f_sweep_tick = ProtoField.uint16("lxrs.sweeptick","Sweep Tick",base.DEC)
f_utc_sec = ProtoField.uint32("lxrs.seconds","UTC Seconds",base.DEC)
f_utc_nsec = ProtoField.uint32("lxrs.nanoseconds","UTC NanoSeconds",base.DEC)


lxrs_proto.fields = {f_sop,f_dsf,f_adt,f_naddr,f_len,f_sample_mode,f_ch_mask,f_sample_rate,f_data_type,f_sweep_tick,f_utc_sec,f_utc_nsec}

-- create a function to dissect it
function lxrs_proto.dissector(buffer,pinfo,tree)

	pinfo.cols.protocol = "lxrs"
	local active_channels  = 0 -- this could be automatically calculated from the channel mask
	
	--local datasubtree = tree:add(lxrs_proto,buffer(),"BCU Temperature")	
	local datasubtree = tree:add(lxrs_proto,buffer(),"LXRS")
	local packet_tree =  datasubtree:add(buffer(offset,6),"PacketHeader")
	local offset=0
	packet_tree:add(f_sop,buffer(offset,1))
	offset = offset + 1
	packet_tree:add(f_dsf,buffer(offset,1))
	offset = offset + 1
	packet_tree:add(f_adt,buffer(offset,1))
	offset = offset + 1
	packet_tree:add(f_naddr,buffer(offset,2))
	offset = offset + 2
	packet_tree:add(f_len,buffer(offset,1))
	local payload_len = buffer(offset,1):int()
	offset = offset + 1
    local channel_tree =  datasubtree:add(buffer(offset,14),"ChannelHeader")
	channel_tree:add(f_sample_mode,buffer(offset,1))
	offset = offset + 1
	channel_tree:add(f_ch_mask,buffer(offset,1))
    channel_mask_bit =  buffer(offset,1):uint()
    for bit=0,7 do
        active_channels = active_channels + bit32.extract(channel_mask_bit,bit,1)
    end
	offset = offset + 1
	channel_tree:add(f_sample_rate,buffer(offset,1))
	offset = offset + 1
	channel_tree:add(f_data_type,buffer(offset,1))
    if buffer(offset,1):uint() == 2 or  buffer(offset,1):uint() == 4 then
        samples_size = 4
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
		local sweep_tree =  sample_tree:add(buffer(offset,samples_size*active_channels),"Sweep " .. sweep_count)
		local ch = 1
		repeat
			sweep_tree:add(buffer(offset,samples_size),"Channel: " .. ch .. " = " .. buffer(offset,samples_size):uint())
			offset = offset + samples_size
			ch = ch + 1
		until (ch == active_channels+1)
		sweep_count = sweep_count + 1
	until (offset == payload_len+6)
	datasubtree:add(buffer(offset,1),"Node RSSI: = " .. buffer(offset,1):uint())
	offset = offset + 1
	datasubtree:add(buffer(offset,1),"Base RSSI: = " .. buffer(offset,1):uint())
	offset = offset + 1
	datasubtree:add(buffer(offset,2),"Checksum: = " .. buffer(offset,2):uint())
	offset = offset + 2
end


-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
udp_table:add(LXRS_UDP_PORT,lxrs_proto)
