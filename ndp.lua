local bit32 = require("bit32_compat")

-------------------------------------------------------
-- This is a Wireshark dissector for the iNet-X packet format
-- http://www.cwc-ae.com/custom/pdfs/White%20Paper_iNET-X_packets.pdf
-------------------------------------------------------

-- Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuidcwc/LuaDissectors


npd_seg_protocol = Proto("npdseg", "NPD Segment")

--DissectorTable.heuristic_new("npdseg.payload", npd_seg_protocol)
--pcall(function () DissectorTable.heuristic_new("npdseg.payload", npd_seg_protocol) end)

local DAR_SEG_FLAGS_FRAG = {[0]="Complete message", [1]="First Fragment", [2]="Middle Fragment", [3]="Last Fragment"}

local fs = npd_seg_protocol.fields
-- Defined the fileds
fs.segcount = ProtoField.uint32("npdseg.count","Segment Count",base.DEC)
fs.timedelta = ProtoField.uint32("npdseg.timedelta","TimeDelta",base.DEC)
fs.segmentlen = ProtoField.uint16("npdseg.segmentlen","Segment Length",base.DEC)
fs.errorcode = ProtoField.uint16("npdseg.errorcode","Error Code",base.HEX)
fs.segflag = ProtoField.uint16("npdseg.flag","Flags",base.HEX, DAR_SEG_FLAGS_FRAG, 0x6)
fs.payload = ProtoField.bytes("npdseg.payload", "Payload", base.DOT)

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

DAR_BSW_CHANNEL = {[0]="Channel A", [1]="Channel B"}
DAR_BSW_PARITY_ERR = {[0]="No Error", [1]="Error"}
DAR_BSW_STOP = {[0]="1 stop bit", [1]="2 stop bits"}
DAR_BSW_PARITY_SELECT = {[0]="Odd", [1]="Even"}
DAR_BSW_PARITY_ENABLE = {[0]="Disabled", [1]="Enabled"}
DAR_BSW_DATABITS = {[0]="8", [1]="7", [2]="6",[3]="5"}
DAR_BSW_PACKETIZATION = {[0]="Sync pattern with fixed data length", [1]="Sync pattern with variable data length", [2]="Packet-based on gap time",[3]="Throughput with fixed data length"}
DAR_BSW_INPUTMODE = {[0]="RS-232", [1]="RS-422"}
DAR_BSW_PAD_ODD_BYTES = {[0]="Disable", [1]="Enable"}
DAR_BSW_ENDIANNESS = {[0]="Big endian", [1]="Little endian"}
DAR_BSW_RELPKTCOUNT = {[0]="Disable", [1]="Enable"}

fs.bsw_channel = ProtoField.uint16("npdseg.bsw.channel","Channel",base.HEX, DAR_BSW_CHANNEL, 0x8000)
fs.bsw_parityerror = ProtoField.uint16("npdseg.bsw.parityerror","Parity Error",base.HEX, DAR_BSW_PARITY_ERR, 0x4000)
fs.bsw_stopbits = ProtoField.uint16("npdseg.bsw.stopbits","Stop Bits",base.HEX, DAR_BSW_STOP, 0x2000)
fs.bsw_parityselect = ProtoField.uint16("npdseg.bsw.parityselect","Parity Select",base.HEX, DAR_BSW_PARITY_SELECT, 0x1000)
fs.bsw_parityenable = ProtoField.uint16("npdseg.bsw.parityenable","Parity Enable",base.HEX, DAR_BSW_PARITY_ENABLE, 0x800)
fs.bsw_databits = ProtoField.uint16("npdseg.bsw.databits","Data Bits",base.HEX, DAR_BSW_DATABITS, 0x600)
fs.bsw_packetization = ProtoField.uint16("npdseg.bsw.packetization","Packetization",base.HEX, DAR_BSW_PACKETIZATION, 0x180)
fs.bsw_inputmode = ProtoField.uint16("npdseg.bsw.inputmode","Input Mode",base.HEX, DAR_BSW_INPUTMODE, 0x40)
fs.bsw_paddodd = ProtoField.uint16("npdseg.bsw.paddodd","Pad odd number of sync bytes with 0 align to 16-bit",base.HEX, DAR_BSW_PAD_ODD_BYTES, 0x20)
fs.bsw_endianness = ProtoField.uint16("npdseg.bsw.endianness","Endianness of data to RV bus",base.HEX, DAR_BSW_ENDIANNESS, 0x10)
fs.bsw_relpktcount = ProtoField.uint16("npdseg.bsw.relpktcount","Relative packet count inserted: starting from an arbitrary number (0–32767)",base.HEX, DAR_BSW_RELPKTCOUNT, 0x8)
fs.bsw_syncpatternbytes = ProtoField.uint16("npdseg.bsw.syncpatternbytes","Sync pattern bytes: number of embedded sync bytes in data packet",base.DEC, nil, 0x7)

function npd_seg_protocol.dissector(buffer, pinfo, tree)

	local v_data_type = tonumber(pinfo.private.data_type)
	local v_segment_cnt = tonumber(pinfo.private.segment_count)
	
	if v_data_type == 0x50 then
		packet_type = "RS232"
	elseif v_data_type == 0x38 then
		packet_type = "ARINC-429"
	elseif v_data_type == 0xD0 then
		packet_type =  "MIL-STD-1553"
	elseif v_data_type == 0x43 then
		packet_type =  "H.264"
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
		local v_sync_byte_count = buffer(offset,2):uint() % 0x8
		
		local v_status_word = buffer(offset, 2):uint()
		local bswtree = subtree:add(buffer(offset, 2), string.format("Block Status Word = 0x%x", buffer(offset, 2):uint()))
		bswtree:add(fs.bsw_channel, v_status_word)
		bswtree:add(fs.bsw_parityerror, v_status_word)
		bswtree:add(fs.bsw_stopbits, v_status_word)
		bswtree:add(fs.bsw_parityselect, v_status_word)
		bswtree:add(fs.bsw_parityenable, v_status_word)
		bswtree:add(fs.bsw_databits, v_status_word)
		bswtree:add(fs.bsw_packetization, v_status_word)
		bswtree:add(fs.bsw_inputmode, v_status_word)
		bswtree:add(fs.bsw_paddodd, v_status_word)
		bswtree:add(fs.bsw_endianness, v_status_word)
		bswtree:add(fs.bsw_relpktcount, v_status_word)
		bswtree:add(fs.bsw_syncpatternbytes, v_status_word)
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
	elseif v_data_type == 0x38 then
		packet_type = "ARINC-429"
		subtree:add(fs.payload, buffer(offset,v_seglen))
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
		subtree:add(fs.payload, buffer(offset,v_msg_len))
		local transaction_tree = subtree:add(buffer(offset, v_msg_len), "Transaction")
		local msgdissector = Dissector.get("milstd1553")
		msgdissector:call(buffer(offset, v_msg_len):tvb(), pinfo, transaction_tree, v_isRT2RT)

	elseif v_data_type == 0x43 then
		local mpegts_block_count = v_seglen / 188
		local msgdissector = Dissector.get("mpegts")
		
		for i=0, mpegts_block_count-1 do
			local transaction_tree = subtree:add(buffer(offset, 188), "MPEGTS Block " .. i)
			msgdissector:call(buffer(offset, 188):tvb(), pinfo, transaction_tree)
			offset = offset + 188
		end
	else
		subtree:add(fs.payload, buffer(offset,v_seglen))
	end

end
-- trivial protocol example
-- declare our protocol
npd_generic_proto = Proto("DARv3","DARv3/NPD Protocol")

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

    pinfo.cols.protocol = "DARv3" -- the name in the wirshark view
    local npd_top_subtree = tree:add(npd_generic_proto,buffer(),"DARv3/NPD Protocol Data")
	
	-- create a subtree for the IENA Header
	subtree = npd_top_subtree:add(buffer(0,20),"Header")
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
	if ( buffer(offset,4):uint() > 2531485487 ) then
		subtree:add(buffer(offset,4),"Date: ERROR. Some time after 2050")
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


local function ndp_heuristic_checker(buffer, pinfo, tree)
    -- guard for length
    local length = buffer:len()
    if length < 28 then return false end

    local version = buffer(0,1):uint()
	if version ~= 0x35 then return false end
	local data_type = buffer(1,1):uint()
	if data_type ~= 0x00 and data_type ~= 0x09 and data_type ~=0x0A and 
	   data_type ~= 0x0b and data_type ~= 0x11 and data_type ~=0x31 and 
	   data_type ~= 0x32 and data_type ~= 0x38 and data_type ~=0x41 and 
	   data_type ~= 0x42 and data_type ~= 0x43 and data_type ~=0x44 and 
	   data_type ~= 0x45 and data_type ~= 0x46 and data_type ~=0x50 and 
	   data_type ~= 0x70 and data_type ~= 0x71 and data_type ~=0xA0 and 
	   data_type ~= 0xA1 and data_type ~= 0xA2 and data_type ~=0xA3 and 
	   data_type ~= 0xA8 and data_type ~= 0xB0 and data_type ~=0xB8 and 
	   data_type ~= 0xC0 and data_type ~= 0xC1 and data_type ~=0xC2 and 
	   data_type ~= 0xC3 and data_type ~= 0xCB and data_type ~=0xCE and 
	   data_type ~= 0xD0 and data_type ~= 0xE0 and data_type ~=0xF0 and 
	   data_type ~= 0xF1 and data_type ~= 0xF9 and data_type ~=0xFD and 
	   data_type ~= 0xFE and data_type ~= 0xFF
	   then return false end

	npd_generic_proto.dissector(buffer, pinfo, tree)
	return true
end
npd_generic_proto:register_heuristic("udp", ndp_heuristic_checker)

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
udp_table:add_for_decode_as(npd_generic_proto)