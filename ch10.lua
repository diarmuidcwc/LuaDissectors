-------------------------------------------------------
-- This is a Wireshark dissector for the Ch10 packet format
-- https://www.irig106.org/docs/106-17/chapter11.pdf
-------------------------------------------------------

-- Copyright 2014 Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuid
-- https://github.com/diarmuidcwc/LuaDissectors

CH10_PORT = 50001
--CH10_PORT = 8010

--require("mil-std-1553")

function ch10_checksum_validate(buffer, checksum, tree)

	
	local v_len = buffer:len()
	local v_checksum = 0
	local v_offset = 0
	repeat
		v_checksum = (v_checksum + buffer(v_offset,2):le_uint()) % 65536
        --tree:add(buffer(v_offset, 2), string.format("Checksum=0x%x Data=0x%x", v_checksum, buffer(v_offset,2):le_uint()))
        v_offset = v_offset + 2
	until v_offset == v_len
	
	if v_checksum  == checksum then
		return true, checksum
	else
		return false, v_checksum
	end

end

ch10_timeprotocol2 =  Proto("ch10time2", "Ch10 Time FMT2")
ch10_timeprotocol1 =  Proto("ch10time1", "Ch10 Time FMT1")

f_ch10timecsd= ProtoField.uint32("ch10.time_csd","Ch10 Time ChannelSpecific",base.HEX)
f_ch10time2csd= ProtoField.uint32("ch10.time2_csd","Ch10 Time ChannelSpecific",base.HEX)
f_ch10time2fmt= ProtoField.uint8("ch10.time2fmt","Ch10 Time Format",base.DEC)

ch10_timeprotocol1.fields = {f_ch10timecsd}
ch10_timeprotocol2.fields = {f_ch10time2csd, f_ch10time2fmt}


function ch10_timeprotocol1.dissector(buffer, pinfo, tree)
	offset = 0
	tree:add_le(f_ch10timecsd, buffer(offset,4))
	offset = offset + 4
	local ms = tonumber(tostring(buffer(offset,1))) * 10
	local s = tonumber(tostring(buffer(offset+1,1)))
    local m = tonumber(tostring(buffer(offset+2,1)))
    local h = tonumber(tostring(buffer(offset+3,1)))
	local doy = tonumber(tostring(buffer(offset+5,1)) ..  tostring(buffer(offset+4,1)))
	
	tree:add(buffer(offset,6), string.format("DOY=%d Time=%d:%d:%d Milliseconds=%d", doy, h,m,s,ms))
	
end 

function ch10_timeprotocol2.dissector(buffer, pinfo, tree)
	offset = 0
	tree:add_le(f_ch10timecsd, buffer(offset,4))
	offset = offset + 4
	tree:add(buffer(offset,4),"Seconds: " .. buffer(offset,4):le_uint())
	tree:add(buffer(offset,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset,4):le_uint()))
	offset = offset + 4
	tree:add(buffer(offset,4),"NanoSeconds: " .. buffer(offset,4):le_uint())

end 


ch10_arincprotocol =  Proto("ch10arinc", "Ch10 ARINC-429")
f_ch10arincmsgcount = ProtoField.uint16("ch10.arincmsgcount","Ch10 ARINC MsgCount",base.DEC)
f_ch10arincgap = ProtoField.uint32("ch10.arincgap","Ch10 ARINC Gap Time",base.DEC)
f_ch10arincflag = ProtoField.uint8("ch10.arincflag","Ch10 ARINC Flag",base.DEC)
f_ch10arincbus = ProtoField.uint8("ch10.arincbus","Ch10 ARINC Bus",base.DEC)

ch10_arincprotocol.fields = {f_ch10arincmsgcount, f_ch10arincgap, f_ch10arincflag, f_ch10arincbus}


function ch10_arincprotocol.dissector(buffer, pinfo, tree)

	local v_buf_len = buffer:len()
    local offset=0
    tree:add_le(f_ch10arincmsgcount, buffer(offset,2))
    offset = offset + 4
	arinc_count = 0
	repeat 
		local arinc_subtree = tree:add(ch10_arincprotocol, buffer(offset, 8), "ARINC Packet " .. arinc_count)
		local v_gap = buffer(offset,3):le_uint() % 0x100000
		arinc_subtree:add_le(f_ch10arincgap, buffer(offset,3), v_gap)
		offset = offset + 2
		local v_flag = buffer(offset,1):uint() / 16
		arinc_subtree:add(f_ch10arincflag, buffer(offset,1), v_flag)
		offset = offset + 1
		arinc_subtree:add(f_ch10arincbus, buffer(offset,1))
		offset = offset + 1
		
		arinc_subtree:add(buffer(offset,4), "Data: " .. buffer(offset,4))
		local parity = buffer(offset,1):uint() / 128
		local ssm = buffer(offset,1):uint()/32 % 4
		local data = ((buffer(offset,1):uint() % 32) * 256 + buffer(offset+1,1):uint() ) * 64 + (buffer(offset+2,1):uint() / 4)
		local sdi = buffer(offset+2,1):uint() % 4
		local label = reverse_byte_bit_order(buffer(offset+3,1):uint()+1)
		arinc_subtree:add(buffer(offset,4),  string.format(" Label: 0o%03o Par:%#01x SSM:%#01x Data:%#05x SDI:%#01x", label, parity, ssm, data, sdi))
		offset = offset + 4
		arinc_count = arinc_count + 1
	until offset == v_buf_len	
	
end


ch10_uartprotocol =  Proto("ch10uart", "Ch10 UART")
f_ch10uartiph = ProtoField.uint32("ch10.uartiphts","Ch10 UART ChannelSpecific",base.HEX)
f_ch10uartiphts_s = ProtoField.uint32("ch10.uartiphts","Ch10 UART Timestamp Sec",base.DEC)
f_ch10uartiphts_us = ProtoField.uint32("ch10.uartiphtsus","Ch10 UART Timestamp USec",base.DEC)
f_ch10uartdatalen = ProtoField.uint32("ch10.uartdatalen","Ch10 UART Data Len",base.DEC)
f_ch10uartsubchannel = ProtoField.uint32("ch10.uartsubchannel","Ch10 UART Subchannel",base.DEC)
f_ch10uartpe = ProtoField.uint32("ch10.uartpe","Ch10 UART Parity Error",base.BOOL)

ch10_uartprotocol.fields = {f_ch10uartiph, f_ch10uartiphts_s, f_ch10uartiphts_us, f_ch10uartdatalen, f_ch10uartsubchannel, f_ch10uartpe}

function ch10_uartprotocol.dissector(buffer, pinfo, tree)

	local v_buf_len = buffer:len()
    local offset=0
    tree:add_le(f_ch10uartiph, buffer(offset,4))
	local iph_ts = buffer(offset,4):le_uint() /  0x80000000
	offset = offset + 4
	uart_count = 0
	repeat 
		if iph_ts == 1 then
			local v_block_len = buffer(offset+8,2):le_uint() + 12
		else
			local v_block_len = buffer(offset,2):le_uint() + 4
		end
		local uart_subtree = tree:add(ch10_uartprotocol, buffer(offset, v_block_len), "UART Packet " .. uart_count)
		if iph_ts == 1 then
			uart_subtree:add_le(f_ch10uartiphts_us, buffer(offset,4))
			offset = offset + 4
			uart_subtree:add_le(f_ch10uartiphts_s, buffer(offset,4))
			offset = offset + 4
		end
		uart_subtree:add_le(f_ch10uartdatalen, buffer(offset,2))
		local v_data_len = buffer(offset,2):le_uint()
		offset = offset + 2
		local v_subchannel = buffer(offset,2):le_uint() % 0x2000
		local v_parity_enable = buffer(offset,2):le_uint() / 0x8000
		uart_subtree:add_le(f_ch10uartsubchannel, buffer(offset,2), v_subchannel)
		uart_subtree:add_le(f_ch10uartpe, buffer(offset,2), v_parity_enable)
		offset = offset + 2
		uart_subtree:add(buffer(offset, v_data_len), "Data")
		offset = offset + v_data_len
		if v_data_len % 2 == 1 then
			uart_subtree:add(buffer(offset, 1), "Padding")
			offset = offset + 1
		end 
		uart_count = uart_count + 1
	until v_buf_len - offset <= 4	
	
end

ch10_pcmprotocol =  Proto("ch10pcm", "Ch10 PCM")

ch10_pcmprotocol.prefs.bytesperminorframe =  Pref.uint( "Bytes per Minor Frame", 0, "Bytes per Minor Frame" )
local fs = ch10_pcmprotocol.fields

local CH10_DATAHDR_MINOR_FRAME_STATUS = {
	[0x0]="Reserved",
	[0x1]="Reserved",
	[0x2]="Minor Frame check",
	[0x3]="Minor Frame Lock",
}
local CH10_DATAHDR_MAJOR_FRAME_STATUS = {
	[0x0]="Major Frame Not Locked",
	[0x1]="Reserved",
	[0x2]="Major Frame Check",
	[0x3]="Major Frame Lock",
}
local CH10_CSD_MODE = {
	[0x0]="Not Enabled",
	[0x1]="Enabled"
}
local CH10_CSD_MODE_ALIGNMENT = {
	[0x0]="16-bit",
	[0x1]="32-bit"
}
local CH10_CSD_MI = {
	[0x0]="First Word is not the beginning of a minor frame",
	[0x1]="First Word is the beginning of a minor frame",
}
local CH10_CSD_MJ = {
	[0x0]="First Word is not the beginning of a major frame",
	[0x1]="First Word is the beginning of a major frame",
}
local CH10_CSD_IPH = {
	[0x0]="The IPHs are omitted for throughput mode",
	[0x1]="The IPHs are required for packed data and unpacked data modes",
}
fs.channel_specific_data = ProtoField.uint32("ch10pcm.channelspecific","Channel SpecificData",base.HEX)
fs.csd_unpacked = ProtoField.uint32("ch10pcm.channelspecific.unpacked","Unpacked Data Mode", base.HEX, CH10_CSD_MODE, 0x40000)
fs.csd_packed = ProtoField.uint32("ch10pcm.channelspecific.packed","Packed Data Mode", base.HEX, CH10_CSD_MODE, 0x80000)
fs.csd_tput = ProtoField.uint32("ch10pcm.channelspecific.tput","Throughput Data Mode", base.HEX, CH10_CSD_MODE, 0x100000)
fs.csd_alignment = ProtoField.uint32("ch10pcm.channelspecific.alignment","Alignment Mode", base.HEX, CH10_CSD_MODE_ALIGNMENT, 0x200000)
fs.csd_minor_lockst = ProtoField.uint32("ch10pcm.channelspecific.minorlockstatus","Minor Frame Lock Status", base.HEX, CH10_DATAHDR_MINOR_FRAME_STATUS, 0xC000000)
fs.csd_major_lockst = ProtoField.uint32("ch10pcm.channelspecific.majorlockstatus","Major Frame Lock Status", base.HEX, CH10_DATAHDR_MAJOR_FRAME_STATUS, 0x3000000)
fs.csd_syncoffset = ProtoField.uint32("ch10pcm.channelspecific.syncoffset","SyncOffset", base.DEC, nil, 0x3FFFF)
fs.csd_mi = ProtoField.uint32("ch10pcm.channelspecific.minorframeindicator","Minor Frame Indicator", base.DEC, CH10_CSD_MI, 0x10000000)
fs.csd_mj = ProtoField.uint32("ch10pcm.channelspecific.majorframeindicator","Major Frame Indicator", base.DEC, CH10_CSD_MJ, 0x20000000)
fs.csd_iph = ProtoField.uint32("ch10pcm.channelspecific.iph","Inter-Packet Header Indicator", base.DEC, CH10_CSD_IPH, 0x40000000)

fs.timestampns = ProtoField.uint64("ch10pcm.timestamp_ns","TimeStamp (ns)",base.DEC)
fs.timestamps = ProtoField.uint64("ch10pcm.timestamp_s","TimeStamp (s)",base.DEC)
fs.datahdr = ProtoField.uint32("ch10pcm.datahdr","Data Header",base.HEX)
fs.datahdr_minor_frame = ProtoField.uint16("ch10pcm.datahdr.minorlck","Minor Frame Status", base.HEX, CH10_DATAHDR_MINOR_FRAME_STATUS, 0xC000)
fs.datahdr_major_frame = ProtoField.uint16("ch10pcm.datahdr.majorlck","Major Frame Status", base.HEX, CH10_DATAHDR_MAJOR_FRAME_STATUS, 0x3000)

function ch10_pcmprotocol.dissector(buffer, pinfo, tree)

	local v_buf_len = buffer:len()
    local offset=0
    local alignment_mode = bit32.band(bit32.rshift(buffer(offset,4):le_uint(), 21), 0x1)
	tree:add_le(fs.channel_specific_data, buffer(offset,4))
	tree:add_le(fs.csd_syncoffset, buffer(offset,4))
	tree:add_le(fs.csd_unpacked, buffer(offset,4))
	tree:add_le(fs.csd_packed, buffer(offset,4))
	tree:add_le(fs.csd_tput, buffer(offset,4))
	tree:add_le(fs.csd_alignment, buffer(offset,4))
	tree:add_le(fs.csd_major_lockst, buffer(offset,4))
	tree:add_le(fs.csd_minor_lockst, buffer(offset,4))
	tree:add_le(fs.csd_mi, buffer(offset,4))
	tree:add_le(fs.csd_mj, buffer(offset,4))
	tree:add_le(fs.csd_iph, buffer(offset,4))
	offset = offset + 4
	local minor_frame_count = 1
	local minor_frame_buffer_len = v_buf_len - 4
	local padding = 0
	if ch10_pcmprotocol.prefs.bytesperminorframe ~= 0 then
		minor_frame_buffer_len = ch10_pcmprotocol.prefs.bytesperminorframe + 10
		if minor_frame_buffer_len % 2 ~= 0 then
			minor_frame_buffer_len = minor_frame_buffer_len + 1
			padding = 1
		end 
		minor_frame_count = (v_buf_len - 4) / (minor_frame_buffer_len)
	end
	tree:add_le(buffer(offset, 2), "Expect PCM Frame Count="..  minor_frame_count)
	--tree:add_le(buffer(offset, 2), "Buffer_len="..  v_buf_len .. " Minorbuflen=" .. minor_frame_buffer_len .. " Bytesperminor=" .. ch10_pcmprotocol.prefs.bytesperminorframe)
	for minor_frame = 1,minor_frame_count,1 
	do
		local minorframetree = tree:add(buffer(offset, minor_frame_buffer_len), "PCM Minor Frame " .. minor_frame)
		minorframetree:add_le(buffer(offset+4,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset+4,4):le_uint()))
		minorframetree:add_le(fs.timestampns, buffer(offset,4))
		offset = offset + 4
		minorframetree:add_le(fs.timestamps, buffer(offset,4))
		offset = offset + 4
        if alignment_mode == 1 then  -- 32b alignment
            minorframetree:add_le(fs.datahdr, buffer(offset,4))
            offset = offset + 2
        else
            minorframetree:add_le(fs.datahdr, buffer(offset,2))
        end 
		minorframetree:add_le(fs.datahdr_minor_frame, buffer(offset,2))
		minorframetree:add_le(fs.datahdr_major_frame, buffer(offset,2))
		offset = offset + 2
		local datatree = minorframetree:add(buffer(offset, minor_frame_buffer_len-10), "Data. (Configure Frame Length in Pref->ch10pcm->Bytes per Minor Frame)")
		datatree:add(buffer(offset, minor_frame_buffer_len-10-padding),   "DATA")
		if padding > 0 then
			datatree:add(buffer(offset+minor_frame_buffer_len-padding-10, padding),   "Padding")
		end 
		offset = offset + minor_frame_buffer_len-10
	end
end

----------------------------------------------------------

local CH10_TTB_VALS = {      [0x00]="Last bit of the last word",
                             [0x01]="First bit of the first word",
                             [0x02]="Last bit of the first word",
                             [0x03]="Reserved" }
local CH10_BSW_BID = {[0X0]="Channel A", [0x1]="Channel B"}
local CH10_BSW_ME = {[0x0]="No Error", [0x1]="Error"}

ch10_1553protocol =  Proto("ch10_1553", "Ch10 MIL-1553-STD")
f_ch101553iph = ProtoField.uint32("ch10.1553iph","Channel Specific Word",base.HEX)
f_ch101553msgcount = ProtoField.uint32("ch10.msgcount","Message Count",base.DEC, nil, 0xFFFFFF)
f_ch10155ttb = ProtoField.uint32("ch10.ttb","Time Tag Bits",base.HEX, CH10_TTB_VALS, 0x80000000)

f_ch101553bsw = ProtoField.uint16("ch10.1553bsw","Block Status Word",base.HEX)
f_ch101553gtw = ProtoField.uint16("ch10.1553gtw","Gap Times Word",base.DEC)
f_ch101553length = ProtoField.uint16("ch10.1553length","Length",base.DEC)


ch10_1553protocol.fields = {f_ch101553iph, f_ch101553msgcount, f_ch101553bsw, f_ch101553gtw, f_ch101553length,  f_ch10155ttb}

function ch10_1553protocol.dissector(buffer, pinfo, tree)

	local v_buf_len = buffer:len()
    local offset=0
    tree:add_le(f_ch101553iph, buffer(offset,4))
    tree:add_le(f_ch101553msgcount, buffer(offset,4))
    tree:add_le(f_ch10155ttb, buffer(offset,4))
	offset = offset + 4
	msg_count = 0
	mil_dissector =  Dissector.get("milstd1553")
	repeat 
		--local v_block_len = buffer(offset+12,2):le_uint() + 12 -- jump to length word
		local msgsubtree = tree:add(ch10_1553protocol, buffer(offset), "MIL-STD-1553 Packet " .. msg_count)
		if ( buffer(offset+4,4):le_uint() > 2531485487 ) then
			msgsubtree:add_le(buffer(offset+4,4),"Date: ERROR. Some time after 2050")
		else
			msgsubtree:add_le(buffer(offset+4,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset+4,4):le_uint()))
		end
		msgsubtree:add_le(buffer(offset,4), "Timestamp(ns)=" .. buffer(offset,4):le_uint64())
		offset = offset + 4
		msgsubtree:add_le(buffer(offset,4), "Timestamp(s)=" .. buffer(offset,4):le_uint64())
		offset = offset + 4
		msgsubtree:add_le(f_ch101553bsw, buffer(offset,2))
		offset = offset + 2
		msgsubtree:add_le(f_ch101553gtw, buffer(offset,2))
		offset = offset + 2
		msgsubtree:add_le(f_ch101553length, buffer(offset,2))
		local v_length_message = buffer(offset,2):le_uint()
		offset = offset + 2
		
		local transaction_tree = msgsubtree:add(mil_dissector, buffer(offset, v_length_message), "Transaction")
		msgdissector = Dissector.get("milstd1553")
		msgdissector:call(buffer(offset, v_length_message):tvb(), pinfo, transaction_tree)
		offset = offset + v_length_message
		msg_count = msg_count + 1
	until v_buf_len - offset <= 4	
	
end


---------------------------------------------------------------------------

local UART_DATA_TYPE = 0x50
local ARINC_DATA_TYPE = 0x38
local TIME1_DATA_TYPE = 0x11
local TIME2_DATA_TYPE = 0x12
local PCM_DATA_TYPE = 0x9
local MIL_STD_1553_DATA_TYPE = 0x19

local CH10_PKT_FLAG_SEC_HDR_VALS = { [0x0]="Packet Secondary Header is not present",
                                     [0x1]="Packet Secondary Header is present" }

local CH10_PKT_FLAG_TS_TIME_SRC_VALS = { [0x0]="Packet Header 48-Bit Relative Time Counter",
                                         [0x1]="Packet Secondary Header Time" }

local CH10_PKT_FLAG_TIME_SYNC_ERR_VALS = { [0x0]="No Relative Time Counter sync error",
                                           [0x1]="Relative Time Counter sync error has occurred" }

local CH10_PKT_FLAG_OVF_ERR_VALS = { [0x0]="No data overflow",
                                     [0x1]="Data overflow has occurred" }

local CH10_PKT_FLAG_TIME_FMT_VALS = { [0x0]="IRIG 106 Chapter 4 binary weighted 48-bit time format",
                                      [0x1]="IEEE-1588 Time format",
                                      [0x2]="Reserved",
                                      [0x3]="Reserved" }

local CH10_PKT_FLAG_CHKSM_VALS = { [0x0]="No data checksum present",
                                   [0x1]="8-bit data checksum present",
                                   [0x2]="16-bit data checksum present",
                                   [0x3]="32-bit data checksum present" }

local CH10_DATA_TYPE_VALS = { [0x00]="Computer Generated Data, Format 0 (User Defined)",
                              [0x01]="Computer Generated Data, Format 1 (Setup Record)",
                              [0x02]="Computer Generated Data, Format 2 (Recording Events)",
                              [0x03]="Computer Generated Data, Format 3 (Recording Index)",
                              [0x04]="Computer Generated Data, Format 4 (Reserved for future use)",
                              [0x05]="Computer Generated Data, Format 5 (Reserved for future use)",
                              [0x06]="Computer Generated Data, Format 6 (Reserved for future use)",
                              [0x07]="Computer Generated Data, Format 7 (Reserved for future use)",
                              [0x08]="PCM Data, Format 0 (Reserved for future use)",
                              [0x09]="PCM Data, Format 1 (IRIG 106 Chapter 4/8)",
                              [0x0A]="PCM Data, Format 2 (Reserved for future use)",
                              [0x0B]="PCM Data, Format 3 (Reserved for future use)",
                              [0x0C]="PCM Data, Format 4 (Reserved for future use)",
                              [0x0D]="PCM Data, Format 5 (Reserved for future use)",
                              [0x0E]="PCM Data, Format 6 (Reserved for future use)",
                              [0x0F]="PCM Data, Format 7 (Reserved for future use)",
                              [0x10]="Time Data, Format 0 (Reserved for future use)",
                              [0x11]="Time Data, Format 1 (IRIG/GPS/RTC)",
                              [0x12]="Time Data, Format 2 (Reserved for future use)",
                              [0x13]="Time Data, Format 3 (Reserved for future use)",
                              [0x14]="Time Data, Format 4 (Reserved for future use)",
                              [0x15]="Time Data, Format 5 (Reserved for future use)",
                              [0x16]="Time Data, Format 6 (Reserved for future use)",
                              [0x17]="Time Data, Format 7 (Reserved for future use)",
                              [0x18]="MIL-STD-1553 Data, Format 0 (Reserved for future use)",
                              [0x19]="MIL-STD-1553 Data, Format 1 (Mil-Std-1553B Data)",
                              [0x1A]="MIL-STD-1553 Data, Format 2 (16PP194 Bus)",
                              [0x1B]="MIL-STD-1553 Data, Format 3 (Reserved for future use)",
                              [0x1C]="MIL-STD-1553 Data, Format 4 (Reserved for future use)",
                              [0x1D]="MIL-STD-1553 Data, Format 5 (Reserved for future use)",
                              [0x1E]="MIL-STD-1553 Data, Format 6 (Reserved for future use)",
                              [0x1F]="MIL-STD-1553 Data, Format 7 (Reserved for future use)",
                              [0x20]="Analog Data, Format 0 (Reserved for future use)",
                              [0x21]="Analog Data, Format 1 (Analog Data)",
                              [0x22]="Analog Data, Format 2 (Reserved for future use)",
                              [0x23]="Analog Data, Format 3 (Reserved for future use)",
                              [0x24]="Analog Data, Format 4 (Reserved for future use)",
                              [0x25]="Analog Data, Format 5 (Reserved for future use)",
                              [0x26]="Analog Data, Format 6 (Reserved for future use)",
                              [0x27]="Analog Data, Format 7 (Reserved for future use)",
                              [0x28]="Discrete Data, Format 0 (Reserved for future use)",
                              [0x29]="Discrete Data, Format 1 (DiscreteData)",
                              [0x2A]="Discrete Data, Format 2 (Reserved for future use)",
                              [0x2B]="Discrete Data, Format 3 (Reserved for future use)",
                              [0x2C]="Discrete Data, Format 4 (Reserved for future use)",
                              [0x2D]="Discrete Data, Format 5 (Reserved for future use)",
                              [0x2E]="Discrete Data, Format 6 (Reserved for future use)",
                              [0x2F]="Discrete Data, Format 7 (Reserved for future use)",
                              [0x30]="Message Data, Format 0 (Generic Message Data)",
                              [0x31]="Message Data, Format 1 (Reserved for future use)",
                              [0x32]="Message Data, Format 2 (Reserved for future use)",
                              [0x33]="Message Data, Format 3 (Reserved for future use)",
                              [0x34]="Message Data, Format 4 (Reserved for future use)",
                              [0x35]="Message Data, Format 5 (Reserved for future use)",
                              [0x36]="Message Data, Format 6 (Reserved for future use)",
                              [0x37]="Message Data, Format 7 (Reserved for future use)",
                              [0x38]="ARINC 429 Data, Format 0 (ARINC429 Data)",
                              [0x39]="ARINC 429 Data, Format 1 (Reserved for future use)",
                              [0x3A]="ARINC 429 Data, Format 2 (Reserved for future use)",
                              [0x3B]="ARINC 429 Data, Format 3 (Reserved for future use)",
                              [0x3C]="ARINC 429 Data, Format 4 (Reserved for future use)",
                              [0x3D]="ARINC 429 Data, Format 5 (Reserved for future use)",
                              [0x3E]="ARINC 429 Data, Format 6 (Reserved for future use)",
                              [0x3F]="ARINC 429 Data, Format 7 (Reserved for future use)",
                              [0x40]="Video Data, Format 0 (MPEG-2/H.264 Video)",
                              [0x41]="Video Data, Format 1 (ISO 13818-1 MPEG-2)",
                              [0x42]="Video Data, Format 2 (ISO 14496 MPEG-4 Part 10 AVC/H.264)",
                              [0x43]="Video Data, Format 3 (Reserved for future use)",
                              [0x44]="Video Data, Format 4 (Reserved for future use)",
                              [0x45]="Video Data, Format 5 (Reserved for future use)",
                              [0x46]="Video Data, Format 6 (Reserved for future use)",
                              [0x47]="Video Data, Format 7 (Reserved for future use)",
                              [0x48]="Image Data, Format 0 (Image Data)",
                              [0x49]="Image Data, Format 1 (Still Imagery)",
                              [0x4A]="Image Data, Format 2 (Reserved for future use)",
                              [0x4B]="Image Data, Format 3 (Reserved for future use)",
                              [0x4C]="Image Data, Format 4 (Reserved for future use)",
                              [0x4D]="Image Data, Format 5 (Reserved for future use)",
                              [0x4E]="Image Data, Format 6 (Reserved for future use)",
                              [0x4F]="Image Data, Format 7 (Reserved for future use)",
                              [0x50]="UART Data, Format 0 (UART Data)",
                              [0x51]="UART Data, Format 1 (Reserved for future use)",
                              [0x52]="UART Data, Format 2 (Reserved for future use)",
                              [0x53]="UART Data, Format 3 (Reserved for future use)",
                              [0x54]="UART Data, Format 4 (Reserved for future use)",
                              [0x55]="UART Data, Format 5 (Reserved for future use)",
                              [0x56]="UART Data, Format 6 (Reserved for future use)",
                              [0x57]="UART Data, Format 7 (Reserved for future use)",
                              [0x58]="IEEE-1394 Data, Format 0 (IEEE-1394 Transaction)",
                              [0x59]="IEEE-1394 Data, Format 1 (IEEE-1394 Physical Layer)",
                              [0x5A]="IEEE-1394 Data, Format 2 (Reserved for future use)",
                              [0x5B]="IEEE-1394 Data, Format 3 (Reserved for future use)",
                              [0x5C]="IEEE-1394 Data, Format 4 (Reserved for future use)",
                              [0x5D]="IEEE-1394 Data, Format 5 (Reserved for future use)",
                              [0xE5]="IEEE-1394 Data, Format 6 (Reserved for future use)",
                              [0x5F]="IEEE-1394 Data, Format 7 (Reserved for future use)",
                              [0x60]="Parallel Data, Format 0 (Parallel Data)",
                              [0x61]="Parallel Data, Format 1 (Reserved for future use)",
                              [0x62]="Parallel Data, Format 2 (Reserved for future use)",
                              [0x63]="Parallel Data, Format 3 (Reserved for future use)",
                              [0x64]="Parallel Data, Format 4 (Reserved for future use)",
                              [0x65]="Parallel Data, Format 5 (Reserved for future use)",
                              [0x66]="Parallel Data, Format 6 (Reserved for future use)",
                              [0x67]="Parallel Data, Format 7 (Reserved for future use)",
                              [0x68]="Ethernet Data, Format 0 (Ethernet Data)",
                              [0x69]="Ethernet Data, Format 1 (Reserved for future use)",
                              [0x6A]="Ethernet Data, Format 2 (Reserved for future use)",
                              [0x6B]="Ethernet Data, Format 3 (Reserved for future use)",
                              [0x6C]="Ethernet Data, Format 4 (Reserved for future use)",
                              [0x6D]="Ethernet Data, Format 5 (Reserved for future use)",
                              [0x6E]="Ethernet Data, Format 6 (Reserved for future use)",
                              [0x6F]="Ethernet Data, Format 7 (Reserved for future use)" }

ch10_protocol =  Proto("ch10", "Chapter 10")
local f = ch10_protocol.fields
f.f_ch10sync = ProtoField.uint16("ch10.sync","Sync",base.HEX)
f.f_ch10chid = ProtoField.uint16("ch10.id","Channel ID",base.HEX)
f.f_ch10pktlen = ProtoField.uint32("ch10.pktlen","Packet Len",base.DEC)
f.f_ch10datalen = ProtoField.uint32("ch10.datalen","Data Len",base.DEC)
f.f_ch10datatypeversion = ProtoField.uint8("ch10.version","Data Type Version",base.HEX)
f.f_ch10sequence = ProtoField.uint8("ch10.sequence","Sequence",base.DEC)
f.f_ch10pktflags = ProtoField.uint8("ch10.pktflag","Packet Flags",base.HEX)

f.f_ch10datatype = ProtoField.uint8("ch10.datatype","Data Type", base.HEX, CH10_DATA_TYPE_VALS)
f.f_ch10rtc_lwr = ProtoField.uint32("ch10.rtclwr","RTC Lwr",base.HEX)
f.f_ch10rtc_upr = ProtoField.uint16("ch10.rtcupr","RTC Upr",base.HEX)
f.f_ch10checksum = ProtoField.uint16("ch10.checksum","Checksum",base.HEX)
f.f_ch10tsns= ProtoField.uint32("ch10.tsns","Timestamp (ns)",base.DEC)
f.f_ch10tss= ProtoField.uint32("ch10.tss","Timestamp (s)",base.DEC)
f.f_ch10hdrcs= ProtoField.uint16("ch10.hdrcs","Header Checksum",base.HEX)

f.pkt_hdr_flag_sec_hdr = ProtoField.uint8("ch10.hdr.flag.sec_hdr", "Packet Secondary Header", base.DEC, CH10_PKT_FLAG_SEC_HDR_VALS, 0x80)
f.pkt_hdr_flag_ts_time_src = ProtoField.uint8("ch10.hdr.flag.ts_time_src", "Intra-Packet Time Stamp Time Source", base.DEC, CH10_PKT_FLAG_TS_TIME_SRC_VALS, 0x40)
f.pkt_hdr_flag_time_sync_err = ProtoField.uint8("ch10.hdr.flag.time_sync_err", "Relative Time Counter Sync Error", base.DEC, CH10_PKT_FLAG_TIME_SYNC_ERR_VALS, 0x20)
f.pkt_hdr_flag_ovf_err = ProtoField.uint8("ch10.hdr.flag.ovf_err", "Data Overflow Error", base.DEC, CH10_PKT_FLAG_OVF_ERR_VALS, 0x10)
f.pkt_hdr_flag_time_fmt = ProtoField.uint8("ch10.hdr.flag.time_fmt", "Packet Secondary Header Time Format", base.DEC, CH10_PKT_FLAG_TIME_FMT_VALS, 0x0C)
f.pkt_hdr_flag_chksm = ProtoField.uint8("ch10.hdr.flag.chksm", "Data Checksum", base.DEC, CH10_PKT_FLAG_CHKSM_VALS, 0x03)

    
function ch10_protocol.dissector(buffer,pinfo,tree)

	local offset=0
	local primary_header_tree = tree:add(buffer(offset, 24), "Primary Header")
	primary_header_tree:add_le(f.f_ch10sync,buffer(offset,2))
	offset = offset + 2
	primary_header_tree:add_le(f.f_ch10chid,buffer(offset,2))
	offset = offset + 2
	local t_pkt_len = primary_header_tree:add_le(f.f_ch10pktlen,buffer(offset,4))
	local v_packet_len = buffer(offset, 4):le_uint()
	local v_packet_len_offset = offset
	offset = offset + 4
	primary_header_tree:add_le(f.f_ch10datalen,buffer(offset,4))
	offset = offset + 4
	primary_header_tree:add_le(f.f_ch10datatypeversion,buffer(offset,1))
	offset = offset + 1
	primary_header_tree:add_le(f.f_ch10sequence,buffer(offset,1))
	offset = offset + 1
	primary_header_tree:add_le(f.f_ch10pktflags,buffer(offset,1))
	local tree_pkt_hdr_flags = primary_header_tree:add(buffer(offset), "Packet Flags")
	tree_pkt_hdr_flags:set_len(1)
	tree_pkt_hdr_flags:add(f.pkt_hdr_flag_sec_hdr, buffer(offset, 1))
	tree_pkt_hdr_flags:add(f.pkt_hdr_flag_ts_time_src, buffer(offset, 1))
	tree_pkt_hdr_flags:add(f.pkt_hdr_flag_time_sync_err, buffer(offset, 1))
	tree_pkt_hdr_flags:add(f.pkt_hdr_flag_ovf_err, buffer(offset, 1))
	tree_pkt_hdr_flags:add(f.pkt_hdr_flag_time_fmt, buffer(offset, 1))
	tree_pkt_hdr_flags:add(f.pkt_hdr_flag_chksm, buffer(offset, 1))

	local v_flag = buffer(offset,1):le_uint()
	offset = offset + 1
	primary_header_tree:add_le(f.f_ch10datatype,buffer(offset,1))
	local v_data_type =  buffer(offset,1):le_uint()
	offset = offset + 1
	primary_header_tree:add_le(f.f_ch10rtc_lwr,buffer(offset,4))
	--tree:add(buffer(offset, 2), "offset=" .. offset)
	offset = offset + 4

	primary_header_tree:add_le(f.f_ch10rtc_upr,buffer(offset,2))
	offset = offset + 2
	primary_header_tree:add_le(f.f_ch10checksum,buffer(offset,2))
	checksum_ok, expected_value = ch10_checksum_validate(buffer(0, offset), buffer(offset,2):le_uint(), tree)
	if not checksum_ok then
		tree:add(buffer(offset, 2), string.format("Checksum Wrong. Expected=0x%x", expected_value))
		tree:add_expert_info(PI_CHECKSUM,PI_WARN)
	end
	offset = offset + 2
	if v_flag / 128 >= 1.0 then
		local sec_hdr = tree:add(ch10_protocol, buffer(offset, 12), "Secondary Header")
		if ( buffer(offset+4,4):le_uint() > 2531485487 ) then
			sec_hdr:add_le(buffer(offset+4,4),"Date: ERROR. Some time after 2050")
		else
			sec_hdr:add_le(buffer(offset+4,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset+4,4):le_uint()))
		end
		sec_hdr:add_le(f.f_ch10tsns,buffer(offset,4))
		offset = offset + 4
		sec_hdr:add_le(f.f_ch10tss,buffer(offset,4))
		offset = offset + 6
		sec_hdr:add_le(f.f_ch10hdrcs,buffer(offset,2))
		checksum_ok, expected_value = ch10_checksum_validate(buffer(offset-10, 10), buffer(offset,2):le_uint(), tree)
		if not checksum_ok then
			tree:add(buffer(offset, 2), string.format("Checksum Wrong. Expected=0x%x", expected_value))
			tree:add_expert_info(PI_CHECKSUM,PI_WARN)
		end
		offset = offset + 2
		add_sec_hdr_len = 12
	else
		add_sec_hdr_len = 0
	end
	-- Check the packet legnth
	local v_expected_payload_len = buffer(offset):len() + 24 + add_sec_hdr_len
	if (v_expected_payload_len) ~= v_packet_len then
		t_pkt_len:add(buffer(v_packet_len_offset,4 ), string.format("ERROR. Expected payload length= %d", v_expected_payload_len))
		t_pkt_len:add_expert_info(PI_MALFORMED,PI_WARN)
	end

	if v_data_type == ARINC_DATA_TYPE then
	local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset), "ARINC")
	ch10arinc_pay = Dissector.get("ch10arinc")
	ch10arinc_pay:call(buffer(offset):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == UART_DATA_TYPE then
	local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset), "UART")
	ch10uart_pay = Dissector.get("ch10uart")
	ch10uart_pay:call(buffer(offset):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == TIME1_DATA_TYPE then
	local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset), "TIME1")
	ch10time_pay = Dissector.get("ch10time1")
	ch10time_pay:call(buffer(offset):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == TIME2_DATA_TYPE then
	local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset), "TIME2")
	ch10time_pay = Dissector.get("ch10time2")
	ch10time_pay:call(buffer(offset):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == PCM_DATA_TYPE then
	local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset), "PCM")
	ch10pcm_pay = Dissector.get("ch10pcm")
	ch10pcm_pay:call(buffer(offset):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == MIL_STD_1553_DATA_TYPE then
	local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset), "MIL-STD-1553")
	ch101553_pay = Dissector.get("ch10_1553")
	ch101553_pay:call(buffer(offset):tvb(),pinfo,ch10pay_subtree)
	else
	local data_subtree = tree:add(ch10_protocol, buffer(offset), "Data")
	end


end

ch10udp_seg_protocol = Proto("ch10UDP", "Chapter 10 UDP")
f_ch10udp_format = ProtoField.uint8("ch10UDP.format","Format",base.DEC)
f_ch10udp_type = ProtoField.uint8("ch10UDP.type","Type / SrcID Length",base.DEC)
f_ch10udp_id = ProtoField.uint32("ch10UDP.channelID","Channel ID",base.DEC)
f_ch10udp_udpsequence = ProtoField.uint32("ch10UDP.udpsequence","UDP Message Sequence",base.DEC)
f_ch10udp_segoffset = ProtoField.uint32("ch10UDP.segoffset","Segment Offset",base.DEC)
-- format 2
f_ch10udp_pktsize = ProtoField.uint32("ch10UDP.packetsize","Packet Size",base.DEC)
f_ch10udp_chsequence = ProtoField.uint32("ch10UDP.chsequence","Channel Sequence",base.DEC)  -- and segmented format 1
f_ch10udp_chnumber = ProtoField.uint16("ch10UDP.chnumbere","Channel Number",base.DEC)
-- format 3
f_ch10udp_offset = ProtoField.uint8("ch10UDP.offset","Offset to Pkt Start",base.DC)
f_ch10udp_datagram_seq = ProtoField.uint8("ch10UDP.datagram_seq","Datagram Sequence Number",base.HEX)
f_ch10udp_srcid = ProtoField.uint16("ch10UDP.srcid","SrcID",base.HEX)

ch10udp_seg_protocol.fields = {f_ch10udp_format, f_ch10udp_type, f_ch10udp_id, f_ch10udp_udpsequence, f_ch10udp_segoffset, f_ch10udp_pktsize, f_ch10udp_chsequence, 
f_ch10udp_chnumber, f_ch10udp_srcid_len, f_ch10udp_srcid, f_ch10udp_offset, f_ch10udp_datagram_seq  }



-- create a function to dissect it
function ch10udp_seg_protocol.dissector(buffer,pinfo,tree)

    pinfo.cols.protocol = "Chapter 10" -- the name in the wirshark view
    local ch10_top_subtree = tree:add(ch10udp_seg_protocol,buffer(),"Ch10 UDP Data")
	
	local v_buffer_len = buffer:len()
	local offset=0
	local v_ch10_format =   bit32.extract(buffer(offset,4):le_uint(),0,4)
    local v_ch10_format_2_expected = bit32.extract(buffer(offset,4):uint(),0,4)
	local v_ch10_format_2_exp_len = buffer(offset+5, 3):uint() * 4
    local v_ch10_type = 0
	local v_segmentoffset = 0
	--ch10_top_subtree:add(buffer(offset,4), v_ch10_format_2_exp_len .. ":" ..v_buffer_len )
	-- because of the differences in endianness we have to use more than just the format field to work out what
	-- format we are in. So take the lenght field and if that matches the buffer length then we can 
	-- asseume that it really is format 2. Otherwise guess that it's format 1
	if v_ch10_format_2_expected == 2 and v_ch10_format_2_exp_len == v_buffer_len-12 then
		--ch10_top_subtree:add(buffer(offset,4), "My Fomat 2")
		ch10_top_subtree:add(f_ch10udp_format, buffer(offset,4), v_ch10_format_2_expected)
		v_ch10_type = bit32.extract(buffer(offset,4):uint(),4,4)
		ch10_top_subtree:add(f_ch10udp_type, buffer(offset,4), v_ch10_type)
	else
		--ch10_top_subtree:add(buffer(offset,4), v_ch10_format_2_expected)
		ch10_top_subtree:add(f_ch10udp_format, buffer(offset,4), v_ch10_format)
		v_ch10_type = bit32.extract(buffer(offset,4):le_uint(),4,4)
		ch10_top_subtree:add(f_ch10udp_type, buffer(offset,4), v_ch10_type)
		offset = offset + 1  
	end 
	  
    if v_ch10_format_2_expected == 2 and v_ch10_format_2_exp_len == v_buffer_len-12 then
		ch10_top_subtree:add(f_ch10udp_udpsequence,buffer(offset,3))
		offset = offset + 4
		local v_seg_offset = buffer(offset,1):uint() * 65536
		offset = offset + 1	
		ch10_top_subtree:add(f_ch10udp_pktsize,buffer(offset, 3))
		if v_ch10_format_2_exp_len ~= v_buffer_len-12 then
			ch10_top_subtree:add(buffer(offset, 2), string.format("Payload Size does not match length of buffer (%d) ", (v_buffer_len -12)/4))
			ch10_top_subtree:add_expert_info(PI_MALFORMED,PI_WARN)
		end 
        offset = offset + 3
		v_seg_offset = v_seg_offset + buffer(offset, 2):uint()
		ch10_top_subtree:add(f_ch10udp_segoffset, buffer(offset, 2), v_seg_offset)
		offset = offset + 2
		ch10_top_subtree:add(f_ch10udp_chnumber,buffer(offset, 2))
		offset = offset + 2
	elseif v_ch10_type >= 1 and v_ch10_format == 1 then
		ch10_top_subtree:add_le(f_ch10udp_udpsequence,buffer(offset,3))
		offset = offset + 3
        ch10_top_subtree:add_le(f_ch10udp_id,buffer(offset, 2))
        offset = offset + 2
        ch10_top_subtree:add_le(f_ch10udp_chsequence,buffer(offset, 1))
        offset = offset + 2
		v_segmentoffset = buffer(offset, 4):le_uint()
        ch10_top_subtree:add_le(f_ch10udp_segoffset,buffer(offset, 4))
		offset = offset + 4
	elseif v_ch10_format == 1 then
		ch10_top_subtree:add_le(f_ch10udp_udpsequence,buffer(offset,3))
		offset = offset + 3
	elseif v_ch10_format == 3 then
		offset = offset + 1  -- Reserved
		ch10_top_subtree:add_le(f_ch10udp_offset,buffer(offset, 2))
		offset = offset + 2
		if v_ch10_type == 0 then
			ch10_top_subtree:add_le(f_ch10udp_datagram_seq, buffer(offset, 4))
			offset = offset + 4
		elseif v_ch10_type == 1 then
			ch10_top_subtree:add_le(f_ch10udp_datagram_seq, buffer(offset, 3))
			offset = offset + 4
			ch10_top_subtree:add_le(f_ch10udp_srcid, buffer(offset, 1),  bit32.extract(buffer(offset,1):le_uint(),4,4))
		elseif v_ch10_type == 2 then
			ch10_top_subtree:add_le(f_ch10udp_datagram_seq, buffer(offset, 3))
			offset = offset + 3
			ch10_top_subtree:add_le(f_ch10udp_srcid, buffer(offset, 1))
			offset = offset + 1
		elseif v_ch10_type == 3 then
			ch10_top_subtree:add_le(f_ch10udp_datagram_seq, buffer(offset, 2))
			offset = offset + 2
			ch10_top_subtree:add_le(f_ch10udp_srcid, buffer(offset, 2),  bit32.extract(buffer(offset,2):le_uint(),4,12))
			offset = offset + 2
		elseif v_ch10_type == 4 then
			ch10_top_subtree:add_le(f_ch10udp_datagram_seq, buffer(offset, 2))
			offset = offset + 2
			ch10_top_subtree:add_le(f_ch10udp_srcid, buffer(offset, 2))
			offset = offset + 2
		end
	end	
			
    if v_segmentoffset == 0 then
		local ch10pay_subtree = tree:add(ch10udp_seg_protocol,buffer(offset),"Ch10 Protocol Data")
		ch10_pay = Dissector.get("ch10")
		ch10_pay:call(buffer(offset):tvb(),pinfo,ch10pay_subtree)
	else
		ch10_top_subtree:add(buffer(offset), string.format("Continuation of segmented packet"))
	end 
    
end


-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register some ports
udp_table:add(CH10_PORT,ch10udp_seg_protocol)
