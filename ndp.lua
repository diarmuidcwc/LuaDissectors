
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

NPD_PORT = 6667
NPD_TTC_PORT = 50001

npd_seg_protocol = Proto("npdseg", "NPD Segment")
f_segcount = ProtoField.uint32("npdseg.count","Segment Count",base.DEC)
f_timedelta = ProtoField.uint32("npdseg.timedelta","TimeDelta",base.DEC)
f_segmentlen = ProtoField.uint16("npdseg.segmentlen","Segment Length",base.DEC)
f_errorcode = ProtoField.uint16("npdseg.errorcode","Error Code",base.HEX)
f_segflag = ProtoField.uint16("npdseg.flag","Flags",base.HEX)

npd_seg_protocol.fields = {f_segcount, f_timedelta,f_segmentlen,f_errorcode,f_segflag }

function npd_seg_protocol.dissector(buffer, pinfo, tree)

	local v_data_type = tonumber(pinfo.private.data_type)
	local v_segment_cnt = tonumber(pinfo.private.segment_count)
	
	if v_data_type == 0x50 then
		packet_type = "RS232"
	elseif v_data_type == 0x38 then
		packet_type = "ARINC-429"
	else
		packet_type =  ""
	end
    subtree = tree:add(buffer(),packet_type .. " Segment ".. v_segment_cnt)
	local offset=0
	subtree:add(f_timedelta,buffer(offset,4))
	offset = offset + 4
	subtree:add(f_segmentlen,buffer(offset,2))
	local v_data_len = buffer(offset,2):uint()
    local v_seglen = buffer(offset,2):uint() - 8
	offset = offset + 2
	subtree:add(f_errorcode,buffer(offset,1))
	offset = offset + 1
	subtree:add(f_segflag,buffer(offset,1))
	offset = offset + 1
	if v_data_type == 0x50 then
		subtree:add(buffer(offset,2), string.format("Block Status Word = 0x%x", buffer(offset,2):uint()))
		local v_sync_byte_count = buffer(offset,2):uint() % 0x8
		offset = offset + 2
		v_seglen = v_seglen -2
		if v_sync_byte_count > 0 then
			for i=1, v_sync_byte_count do
				subtree:add(buffer(offset,1), string.format("Sync Byte = %x", buffer(offset,1):uint()))
				offset = offset + 1
				v_seglen = v_seglen -1
			end
		end
		subtree:add(buffer(offset,v_seglen), string.format("Data (%d bytes)", v_seglen))
	elseif pinfo.private.data_type == 0x38 then
		packet_type = "ARINC-429"
	elseif v_data_type == 0xA1 or v_data_type == 0x09 then
		packet_type = "MPCM"
		subtree:add(buffer(offset,1), string.format("SFID = 0x%x", buffer(offset,1):uint()))
		offset = offset + 4
		v_seglen = v_seglen - 4
		repeat
			subtree:add(buffer(offset,2), string.format("Placed Word = %x", buffer(offset,2):uint()))
			offset = offset + 2
			v_seglen = v_seglen -2
		until v_seglen == 0
	else
		subtree:add(buffer(offset,v_seglen), "Payload")
	end
    

end

-- trivial protocol example
-- declare our protocol
npd_generic_proto = Proto("TTC_NPD","TTC NPD Protocol")

-- Declare a few fields
f_version = ProtoField.uint8("NPD.version","Version-HDR_Len",base.HEX)
f_datatype = ProtoField.uint8("NPD.datatype","DataType",base.HEX)
f_packetlen = ProtoField.uint16("NPD.packetlen","Packet Length",base.DEC)
f_cfgcnt = ProtoField.uint8("NPD.cfgcnt","Configuration Count",base.DEC)
f_flags = ProtoField.uint8("NPD.flags","Flags",base.DEC)
f_sequence = ProtoField.uint16("NPD.sequence","Sequence Number",base.DEC)
f_datasrc = ProtoField.uint32("NPD.datasrc","Data Source",base.HEX)
f_mcast = ProtoField.ipv4("NPD.mcast","Multicast Address",base.HEX)
f_timestamp = ProtoField.uint32("NPD.timestamp","Timestamp",base.DEC)


npd_generic_proto.fields = {f_version,f_datatype,f_packetlen,f_cfgcnt,f_flags,f_sequence,f_datasrc,f_mcast,f_timestamp }


-- create a function to dissect it
function npd_generic_proto.dissector(buffer,pinfo,tree)

    pinfo.cols.protocol = "NPD" -- the name in the wirshark view
    local npd_top_subtree = tree:add(npd_generic_proto,buffer(),"NPD Protocol Data")
	
	-- create a subtree for the IENA Header
	subtree = npd_top_subtree:add(buffer(0,20),"NPD Header")
	local offset=0
	subtree:add(f_version,buffer(offset,1))
	offset = offset + 1
	subtree:add(f_datatype,buffer(offset,1))
	pinfo.private.data_type = buffer(offset,1):uint()
	offset = offset + 1
	subtree:add(f_packetlen,buffer(offset,2))
    local v_pkt_len_32bit = buffer(offset,2):uint()
	offset = offset + 2
	subtree:add(f_cfgcnt,buffer(offset,1))
	offset = offset + 1
	subtree:add(f_flags,buffer(offset,1))
	offset = offset + 1
	subtree:add(f_sequence,buffer(offset,2))
	offset = offset + 2
	subtree:add(f_datasrc,buffer(offset,4))
	offset = offset + 4
	subtree:add(f_mcast,buffer(offset,4))
	offset = offset + 4
	subtree:add(f_timestamp,buffer(offset,4))
	if ( buffer(offset,4):uint() > 1576800000 ) then
		subtree:add(buffer(offset,4),"Date: ERROR. Some time after 2020")
	else
		subtree:add(buffer(offset,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset,4):uint()))
	end
	offset = offset + 4
    
    segment = 0
    repeat
        local seg_len = buffer(offset+4,2):uint()
        local pad_len = 0
        if seg_len % 4 == 0 then
            pad_len = 0
        else
            pad_len = 4 - (seg_len % 4)            
        end
        --npd_top_subtree:add(buffer(offset, seg_len + pad_len), "offset: "..offset.. " Pad: " .. pad_len .. " Seg Len: " .. seg_len .. " pkt Len: "..v_pkt_len_32bit)
        npdseg_dissector = Dissector.get("npdseg")
		pinfo.private.segment_count = segment
        npdseg_dissector:call(buffer(offset, seg_len + pad_len):tvb(), pinfo, npd_top_subtree)
        offset = offset + seg_len + pad_len
        segment = segment + 1
		
    until (offset >= (v_pkt_len_32bit*4))
    
    
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register some ports
udp_table:add(NPD_PORT,npd_generic_proto)
udp_table:add(NPD_TTC_PORT,npd_generic_proto)
