
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

NPD_PORT = 1024
NPD_TTC_PORT = 50001

npd_seg_protocol = Proto("npdseg", "NPD Segment")

local DAR_SEG_FLAGS_FRAG = {[0]="Complete message", [1]="First Fragment", [2]="Middle Fragment", [3]="Last Fragment"}

local fs = npd_seg_protocol.fields
-- Defined the fileds
fs.segcount = ProtoField.uint32("npdseg.count","Segment Count",base.DEC)
fs.timedelta = ProtoField.uint32("npdseg.timedelta","TimeDelta",base.DEC)
fs.segmentlen = ProtoField.uint16("npdseg.segmentlen","Segment Length",base.DEC)
fs.errorcode = ProtoField.uint16("npdseg.errorcode","Error Code",base.HEX)
fs.segflag = ProtoField.uint16("npdseg.flag","Flags",base.HEX, DAR_SEG_FLAGS_FRAG, 0x7)

-- MIL-STD-1553
DAR_BSW_CLASS = {[0]="Normal", [1]="Unclassified", [2]="Classified", [3]="Reserved"}
DAR_BSW_ID = {[0]="Bus A", [1]="Bus B"}
DAR_BSW_ERR = {[0]="No Error", [1]="Error occurred"}
DAR_BSW_RT = {[0]="Not RT to RT", [1]="RT to RT"}
DAR_BSW_FMT_ERR = {[0]="No Format Error", [1]="Format Error"}
DAR_BSW_TIMEOUT = {[0]="No Timeout", [1]="Timeout"}
DAR_BSW_WC_ERR = {[0]="No Word Count Error", [1]="Word Count Error"}
DAR_BSW_SYNC_ERR = {[0]="No Sync Error", [1]="Sync Error"}
DAR_BSW_INVALID_ERR = {[0]="No Invalid Word Error", [1]="Invalid Word Error"}

fs.bsw_class = ProtoField.uint16("npdseg.bsw.class","Classification",base.HEX, DAR_BSW_CLASS, 0xC000)
fs.bsw_id = ProtoField.uint16("npdseg.bsw.id","Bus ID",base.HEX, DAR_BSW_ID, 0x2000)
fs.bsw_err = ProtoField.uint16("npdseg.bsw.error","Message Error",base.HEX, DAR_BSW_ERR, 0x1000)
fs.bsw_rt = ProtoField.uint16("npdseg.bsw.rt","RT to RT",base.HEX, DAR_BSW_RT, 0x800)
fs.bsw_fmt = ProtoField.uint16("npdseg.bsw.fmt","Format Error",base.HEX, DAR_BSW_FMT_ERR, 0x400)
fs.bsw_timeout = ProtoField.uint16("npdseg.bsw.timeout","Message Timeout",base.HEX, DAR_BSW_TIMEOUT, 0x200)
fs.bsw_wc_err = ProtoField.uint16("npdseg.bsw.wcerr","Word Count Error",base.HEX, DAR_BSW_WC_ERR, 0x40)
fs.bsw_sync = ProtoField.uint16("npdseg.bsw.sync","Sync Error",base.HEX, DAR_BSW_SYNC_ERR, 0x10)
fs.bsw_invalid = ProtoField.uint16("npdseg.bsw.invalid","Invalid Word",base.HEX, DAR_BSW_INVALID_ERR, 0x8)

function npd_seg_protocol.dissector(buffer, pinfo, tree)

	local v_data_type = tonumber(pinfo.private.data_type)
	local v_segment_cnt = tonumber(pinfo.private.segment_count)
	
	if v_data_type == 0x50 then
		packet_type = "RS232"
	elseif v_data_type == 0x38 then
		packet_type = "ARINC-429"
	elseif v_data_type == 0xD0 then
		packet_type =  "MIL-STD-1553"
	else
		packet_type =  ""
	end
    subtree = tree:add(buffer(),packet_type .. " Segment ".. v_segment_cnt)
	local offset=0
	subtree:add(fs.timedelta,buffer(offset,4))
	offset = offset + 4
	subtree:add(fs.segmentlen,buffer(offset,2))
	local v_data_len = buffer(offset,2):uint()
    local v_seglen = buffer(offset,2):uint() - 8
	offset = offset + 2
	subtree:add(fs.errorcode,buffer(offset,1))
	offset = offset + 1
	subtree:add(fs.segflag,buffer(offset,1))


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
	elseif ((v_data_type == 0xD0) or (v_data_type == 0x03)) then
		packet_type = "MIL-STD-1553"

		local v_status_word = buffer(offset, 2):uint()
		local v_isRT2RT  = bit32.extract(v_status_word,11,1) 
	
		local bswtree = subtree:add(buffer(offset, 2), string.format("Block Status Word = 0x%x", buffer(offset, 2):uint()))
		bswtree:add(fs.bsw_class, v_status_word)
		bswtree:add(fs.bsw_id, v_status_word)
		bswtree:add(fs.bsw_err, v_status_word)
		bswtree:add(fs.bsw_rt, v_status_word)
		bswtree:add(fs.bsw_fmt, v_status_word)
		bswtree:add(fs.bsw_timeout, v_status_word)
		bswtree:add(fs.bsw_wc_err, v_status_word)
		bswtree:add(fs.bsw_sync, v_status_word)
		bswtree:add(fs.bsw_invalid, v_status_word)
		offset = offset + 2
		
		
		local v_gap2 =  buffer(offset,1):uint()
		subtree:add(buffer(offset,1), string.format("RT-RT GAP2 = 0x%x (%.1f us)", v_gap2, v_gap2*.1))
		offset = offset + 1

		local v_gap1 =  buffer(offset,1):uint()
		subtree:add(buffer(offset,1), string.format("RT-RT GAP1 = 0x%x (%.1f us)", v_gap1, v_gap1*.1))
		offset = offset + 1
		
		local v_msg_len = v_data_len - 12
		local transaction_tree = subtree:add(milstd1553_proto, buffer(offset, v_msg_len), "Transaction")
		msgdissector = Dissector.get("milstd1553")
		msgdissector:call(buffer(offset, v_msg_len):tvb(), pinfo, transaction_tree, v_isRT2RT)

	else
		subtree:add(buffer(offset,v_seglen), "Payload")
	end

end
-- trivial protocol example
-- declare our protocol
npd_generic_proto = Proto("TTC_NPD","TTC NPD Protocol")

local DAR_FLAGS_RTP = {[0]="IEEE 1558 Timestamp", [1]="Relative Time Counter Timestamp"}
local DAR_FLAGS_FRAG = {[0]="Normal IP Fragmentation", [1]="NPD Fragmentation"}
local DAR_FLAGS_TS = {[0]="Synchronised Time Source", [1]="Free-Running Time Source"}
-- Declare a few fields
local f = npd_generic_proto.fields

f.version = ProtoField.uint8("NPD.version","Version-HDR_Len",base.HEX)
f.datatype = ProtoField.uint8("NPD.datatype","DataType",base.HEX)
f.packetlen = ProtoField.uint16("NPD.packetlen","Packet Length",base.DEC)
f.cfgcnt = ProtoField.uint8("NPD.cfgcnt","Configuration Count",base.DEC)
f.flags = ProtoField.uint8("NPD.flags","Flags",base.DEC)
f.flags_rtp = ProtoField.uint8("NPD.flags.rtcp","Flags",base.DEC, DAR_FLAGS_RTP, 0x4)
f.flags_frag = ProtoField.uint8("NPD.flags.frag","Flags",base.DEC, DAR_FLAGS_FRAG, 0x2)
f.flags_ts = ProtoField.uint8("NPD.flags.ts","Flags",base.DEC, DAR_FLAGS_TS, 0x1)

f.sequence = ProtoField.uint16("NPD.sequence","Sequence Number",base.DEC)
f.datasrc = ProtoField.uint32("NPD.datasrc","Data Source",base.HEX)
f.mcast = ProtoField.ipv4("NPD.mcast","Multicast Address",base.HEX)
f.timestamp = ProtoField.uint32("NPD.timestamp","Timestamp",base.DEC)



-- create a function to dissect it
function npd_generic_proto.dissector(buffer,pinfo,tree)

    pinfo.cols.protocol = "NPD" -- the name in the wirshark view
    local npd_top_subtree = tree:add(npd_generic_proto,buffer(),"NPD Protocol Data")
	
	-- create a subtree for the IENA Header
	subtree = npd_top_subtree:add(buffer(0,20),"NPD Header")
	local offset=0
	subtree:add(f.version,buffer(offset,1))
	offset = offset + 1
	subtree:add(f.datatype,buffer(offset,1))
	pinfo.private.data_type = buffer(offset,1):uint()
	offset = offset + 1
	subtree:add(f.packetlen,buffer(offset,2))
    local v_pkt_len_32bit = buffer(offset,2):uint()
	offset = offset + 2
	subtree:add(f.cfgcnt,buffer(offset,1))
	offset = offset + 1
	subtree:add(f.flags,buffer(offset,1))
	subtree:add(f.flags_rtp,buffer(offset,1))
	subtree:add(f.flags_frag,buffer(offset,1))
	subtree:add(f.flags_ts,buffer(offset,1))
	offset = offset + 1
	subtree:add(f.sequence,buffer(offset,2))
	offset = offset + 2
	subtree:add(f.datasrc,buffer(offset,4))
	offset = offset + 4
	subtree:add(f.mcast,buffer(offset,4))
	offset = offset + 4
	subtree:add(f.timestamp,buffer(offset,4))
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
		if seg_len < 8 then
			npd_top_subtree:add(buffer(offset), "Illegal Segment Length = %d", seg_len)
			npd_top_subtree:add_expert_info(PI_MALFORMED,PI_ERROR)
			offset = v_pkt_len_32bit*4
		else
			--npd_top_subtree:add(buffer(offset), "offset: "..offset.. " Pad: " .. pad_len .. " Seg Len: " .. seg_len .. " pkt Len: "..v_pkt_len_32bit)
			npdseg_dissector = Dissector.get("npdseg")
			pinfo.private.segment_count = segment
			npdseg_dissector:call(buffer(offset, seg_len + pad_len):tvb(), pinfo, npd_top_subtree)
			offset = offset + seg_len + pad_len
			segment = segment + 1
		end
    until (offset >= (v_pkt_len_32bit*4))


end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register some ports
udp_table:add(NPD_PORT,npd_generic_proto)
udp_table:add(NPD_TTC_PORT,npd_generic_proto)
