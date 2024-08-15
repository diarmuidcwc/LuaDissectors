-------------------------------------------------------
-- This is a Wireshark dissector for the Ch10 packet format
-- https://www.irig106.org/docs/106-17/chapter11.pdf
-------------------------------------------------------

-- Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuidcwc/LuaDissectors



require("common")

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

-------------------------------
---    CH10 Video Format 0
-------------------------------

ch10_video0 =  Proto("ch10video0", "Ch10 Video FMT0")
local video1 = ch10_video0.fields
local CH10_VIDEO_IPH = {
	[0x0]="Not Present",
	[0x1]="Present",
}

local CH10_VIDEO_SRS = {
	[0x0]="STC is not synchronized with the 10-MHz RTC",
	[0x1]="STC is synchronized with the 10-MHz RTC",
}
local CH10_VIDEO_BA = {
	[0x0]="Little Endian",
	[0x1]="Big Endian",
}
video1.csw_iph = ProtoField.uint32("ch10.video0.iph","Intra Packet Header", base.HEX, CH10_VIDEO_IPH, 0x40000000)
video1.csw_srs = ProtoField.uint32("ch10.video0.srs","STC/RTC Sync (SRS)", base.HEX, CH10_VIDEO_SRS, 0x20000000)
video1.csw_ba = ProtoField.uint32("ch10.video0.ba","Byte Alignment", base.HEX, CH10_VIDEO_BA, 0x800000)


function ch10_video0.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "CH10 - Video FMT0"
	offset = 0
	tree:add_le(video1.csw_iph, buffer(offset,4))
	tree:add_le(video1.csw_srs, buffer(offset,4))
	tree:add_le(video1.csw_ba, buffer(offset,4))
	local iph_present = math.floor(buffer(offset,4):le_uint() / 0x40000000 )
	if iph_present == 1 then
		iph_len = 8
	else 
		iph_len = 0
	end
	offset = offset + 4
	local buf_len = buffer:len()
	local video_block_count = (buf_len - 4) / (188 + iph_len)
	for blk_count = 1, video_block_count, 1 do
		local block_subtree = tree:add(ch10_video0, buffer(offset, 188+iph_len), "VIDEO Block #" .. blk_count)
		if iph_present == 1 then
			block_subtree:add_le(buffer(offset,4), "Time LSLW")
			offset = offset + 4
			block_subtree:add_le(buffer(offset,4), "Time MSLW")
			offset = offset + 4
		end
		--block_subtree:add(buffer(offset, 188), "Video TS")
		mpegts_diss = Dissector.get("mpegts")
		buff_swap = endian_swap(buffer(offset,188):bytes())
		mpegts_diss:call(buff_swap:tvb(),pinfo,block_subtree)
		offset = offset + 188
	end
	
end 

-------------------------------
---    CH10 Video Format 2
-------------------------------

ch10_video2 =  Proto("ch10video2", "Ch10 Video FMT2")
local video2 = ch10_video2.fields

local CH10_VIDEO_TP = {
	[0x0]="Transport Data Stream",
	[0x1]="Program Data Stream",
}
video2.csw_iph = ProtoField.uint32("ch10.video2.iph","Intra Packet Header", base.HEX, CH10_VIDEO_IPH, 0x80000)
video2.csw_srs	 = ProtoField.uint32("ch10.video2.srs","STC/RTC Sync (SRS)", base.HEX, CH10_VIDEO_SRS, 0x100000)
video2.csw_tp	 = ProtoField.uint32("ch10.video2.tp","Type", base.HEX, CH10_VIDEO_TP, 0x1000)


function ch10_video2.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "CH10 - Video FMT2"
	offset = 0
	tree:add_le(video2.csw_iph, buffer(offset,4))
	tree:add_le(video2.csw_srs, buffer(offset,4))
	tree:add_le(video2.csw_tp, buffer(offset,4))
	local iph_present = math.floor(buffer(offset,4):le_uint() / 0x80000 )
	if iph_present == 1 then
		iph_len = 8
	else 
		iph_len = 0
	end
	offset = offset + 4
	local buf_len = buffer:len()
	local video_block_count = (buf_len - 4) / (188 + iph_len)
	for blk_count = 1, video_block_count, 1 do
		local block_subtree = tree:add(ch10_video0, buffer(offset, 188+iph_len), "VIDEO Block #" .. blk_count)
		if iph_present == 1 then
			block_subtree:add_le(buffer(offset,4), "Time LSLW")
			offset = offset + 4
			block_subtree:add_le(buffer(offset,4), "Time MSLW")
			offset = offset + 4
		end
		mpegts_diss = Dissector.get("mpegts")
		mpegts_diss:call(buffer(offset, 188):tvb(),pinfo,block_subtree)
		offset = offset + 188
	end
	
end 



-------------------------------
---    CH10 Time Format 1
-------------------------------

ch10_timeprotocol1 =  Proto("ch10time1", "Ch10 Time FMT1")
local ftime1 = ch10_timeprotocol1.fields
local CH10_TIME1_ITS= {
	[0x0]="Freewheeling",
	[0x1]="Freewheeling from .TIME",
	[0x2]="Freewheeling from RMM",
	[0x3]="Locked to IRIG",
	[0x4]="Locked to GPS",
	[0x5]="Locked to NTP",
	[0x6]="Locked to PTP",
	[0x7]="Locked to PCM",
}
local CH10_TIME1_DATE = {
	[0x0]="IRIG day avail",
	[0x1]="Month and Year Avail",
}
local CH10_TIME1_DATE_LEAP = {
	[0x0]="Not leap year",
	[0x1]="Leap Year",
}
local CH10_TIME1_FMT = {
	[0x0]="IRIG-B",
	[0x1]="IRIG-A",
	[0x2]="IRIG-G",
	[0x3]="RTC",
	[0x4]="UTC from GPS",
	[0x5]="GPS",
}
local CH10_TIME1_SRC = {
	[0x0]="Internal",
	[0x1]="External",
	[0x2]="RMM",
}
ftime1.csw_its = ProtoField.uint32("ch10.time1.its","IRIG Time Source", base.HEX, CH10_TIME1_ITS, 0xF000)
ftime1.csw_date = ProtoField.uint32("ch10.time1.date","Date", base.HEX, CH10_TIME1_DATE, 0x200)
ftime1.csw_leap = ProtoField.uint32("ch10.time1.leap","Leap Year", base.HEX, CH10_TIME1_DATE_LEAP, 0x100)
ftime1.csw_fmt = ProtoField.uint32("ch10.time1.fmt","Format", base.HEX, CH10_TIME1_FMT, 0xF0)
ftime1.csw_src = ProtoField.uint32("ch10.time1.src","Source", base.HEX, CH10_TIME1_SRC, 0xF)


function ch10_timeprotocol1.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "CH10 - Time FMT1"
	offset = 0
	tree:add_le(ftime1.csw_its, buffer(offset,4))
	tree:add_le(ftime1.csw_date, buffer(offset,4))
	tree:add_le(ftime1.csw_leap, buffer(offset,4))
	tree:add_le(ftime1.csw_fmt, buffer(offset,4))
	tree:add_le(ftime1.csw_src, buffer(offset,4))
	local v_yr_available = math.floor(buffer(offset,4):le_uint() / 512 )
	offset = offset + 4
	local ms = tonumber(tostring(buffer(offset,1))) * 10
	local s = tonumber(tostring(buffer(offset+1,1)))
    local m = tonumber(tostring(buffer(offset+2,1)))
    local h = tonumber(tostring(buffer(offset+3,1)))
	if v_yr_available == 1 then
		local doy = tonumber(tostring(buffer(offset+4,1)))
		local month = tonumber(tostring(buffer(offset+5,1)))
		local year = tonumber(tostring(buffer(offset+7,1)) ..  tostring(buffer(offset+5,1)))
		tree:add(buffer(offset,6), string.format("Year=%d Month=%d DOY=%d Time=%02d:%02d:%02d Milliseconds=%03d",year, month, doy, h,m,s,ms))
	else
		local doy = tonumber(tostring(buffer(offset+5,1)) ..  tostring(buffer(offset+4,1)))
		tree:add(buffer(offset,6), string.format("DOY=%d Time=%02d:%02d:%02d Milliseconds=%03d", doy, h,m,s,ms))
	end
	
	
	
end 

ch10_timeprotocol2 =  Proto("ch10time2", "Ch10 Time FMT2")
local ftime2 = ch10_timeprotocol2.fields
local CH10_TIME2_NTF= {
	[0x0]="NTP",
	[0x1]="PTP 2002",
	[0x2]="PTP 2008",
}
local CH10_TIME2_TS= {
	[0x0]="Time Not Valid",
	[0x1]="Time Valid",
}

ftime2.csw_ntf = ProtoField.uint32("ch10.time2.ntf","Ch10 Time Network Time Format", base.HEX, CH10_TIME2_NTF, 0xF0)
ftime2.csw_ts = ProtoField.uint32("ch10.time2.ts","Ch10 Time Status", base.HEX, CH10_TIME2_TS, 0xF)
ftime2.seconds = ProtoField.uint8("ch10.time2.seconds","Ch10 Time Seconds",base.DEC)
ftime2.fracseconds = ProtoField.uint8("ch10.time2.fracseconds","Ch10 Time Fractional Seconds",base.DEC)

function ch10_timeprotocol2.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "CH10 - Time FMT2"
	offset = 0
	tree:add_le(ftime2.csw_ntf, buffer(offset,4))
	tree:add_le(ftime2.csw_ts, buffer(offset,4))
	offset = offset + 4
	sec = buffer(offset, 4):le_uint()
	nsec = buffer(offset + 4, 4):le_uint()
	tree:add_le(ftime2.seconds, buffer(offset, 4))
	tree:add_le(ftime2.fracseconds, buffer(offset + 4, 4))
	local datestr = os.date("!%H:%M:%S %d %b %Y" , sec)
	tree:add(buffer(offset,8), string.format("Time = %s Nanoseconds = %s",  datestr, nsec))
end 

ch10_analogprotocol =  Proto("ch10analogfmt1", "Ch10 Analog FMT1")
local analogfmt1 = ch10_analogprotocol.fields
local CH10_ANALOG_SAME= {
	[0x0]="Unique CSDW per channel",
	[0x1]="One CSDW",
}
local CH10_ANALOG_MODE= {
	[0x0]="Packed",
	[0x1]="Unpacked LSB padded",
	[0x2]="Reserved",
	[0x3]="Unpacked MSB padded",
}
local CH10_ANALOG_LENGTH = {}
for i=0, 63 do
	if i == 0 then
		CH10_ANALOG_LENGTH[i] = string.format("%d bits", 64)
	else
		CH10_ANALOG_LENGTH[i] = string.format("%d bits", i)
	end
end

analogfmt1.same = ProtoField.uint32("ch10.analog.SAME","Ch10 Analog SAME", base.HEX, CH10_ANALOG_SAME, 0x10000000)
analogfmt1.factor = ProtoField.uint32("ch10.analog.factor","Ch10 Analog Factor", base.HEX, nil, 0xF000000)
analogfmt1.subchannelcount = ProtoField.uint32("ch10.analog.subchannel","Ch10 Analog Sub Channel Count", base.DEC, nil, 0xFF0000)
analogfmt1.subchannelid = ProtoField.uint32("ch10.analog.subchannelid","Ch10 Analog Sub Channel ID", base.HEX, nil, 0xFF00)
analogfmt1.length = ProtoField.uint32("ch10.analog.length","Ch10 Analog Length", base.DEC, CH10_ANALOG_LENGTH, 0xFC)
analogfmt1.mode = ProtoField.uint32("ch10.analog.mode","Ch10 Analog Mode", base.HEX, CH10_ANALOG_MODE, 0x3)


function ch10_analogprotocol.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "CH10 - Analog FMT1"
	offset = 0 
	tree:add_le(analogfmt1.same, buffer(offset,4))
	tree:add_le(analogfmt1.factor, buffer(offset,4))
	tree:add_le(analogfmt1.subchannelcount, buffer(offset,4))
	tree:add_le(analogfmt1.subchannelid, buffer(offset,4))
	tree:add_le(analogfmt1.length, buffer(offset,4))
	tree:add_le(analogfmt1.mode, buffer(offset,4))
	offset = offset + 4
	tree:add(buffer(offset), "Data")

end 

--------------
----- CAN Bus 
--------------

ch10_canprotocol =  Proto("ch10can", "Ch10 CAN Bus")
local canfields = ch10_canprotocol.fields
local CH10_CAN_DE= {
	[0x0]="No Data Error",
	[0x1]="Data Error",
}
local CH10_CAN_FE= {
	[0x0]="No Format Error",
	[0x1]="Format Error",
}

canfields.csw = ProtoField.uint32("ch10.can.csw","Channel Specific Word", base.HEX)
canfields.msgcnt = ProtoField.uint32("ch10.can.messagecnt","Message Count", base.DEC, nil, 0xFFFF)

canfields.ns = ProtoField.uint64("ch10.can.timestamp_ns","TimeStamp (ns)",base.DEC)
canfields.s = ProtoField.uint64("ch10.can.timestamp_s","TimeStamp (s)",base.DEC)
canfields.rtc = ProtoField.uint64("ch10.can.rtc","Relative Time Counter",base.DEC)

canfields.ipmh = ProtoField.uint32("ch10.can.ipmh","Intra-Packet Message Header", base.HEX)
canfields.de = ProtoField.uint32("ch10.can.de","Data Error", base.HEX, CH10_CAN_DE, 0x80000000)
canfields.fe = ProtoField.uint32("ch10.can.fe","Format Error", base.HEX, CH10_CAN_FE, 0x40000000)
canfields.subchannel = ProtoField.uint32("ch10.can.subchannel","Subchannel", base.DEC, nil, 0xFF0000)
canfields.length = ProtoField.uint32("ch10.can.length","Message Length", base.DEC, nil, 0xFF)

local CH10_CAN_IDE= {
	[0x0]="11-bit standard",
	[0x1]="29-bit extended",
}
canfields.ipid = ProtoField.uint32("ch10.can.ipid","Intra-Packet ID Word", base.HEX)
canfields.busid = ProtoField.uint32("ch10.can.busid","Bus ID", base.HEX, nil, 0x1FFFFFFF)
canfields.rtr = ProtoField.uint32("ch10.can.rtr","Remote Transmission Request", base.HEX, nil, 0x40000000)
canfields.ide = ProtoField.uint32("ch10.can.ide","Identifier Extension Bit", base.HEX, CH10_CAN_IDE, 0x80000000)

function ch10_canprotocol.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "CH10 - CAN Bus"
	offset = 0 
	tree:add_le(canfields.csw, buffer(offset,4))
	tree:add_le(canfields.msgcnt, buffer(offset,4))
	local buf_len = buffer:len()
	local can_msg_cnt = buffer(offset,4):le_uint()
	local msg_len = buffer(offset+12,1):le_uint()
	offset = offset + 4
	for msg_count = 1, can_msg_cnt, 1
	do
		if msg_len + offset > buf_len then
			sel_len = buf_len - offset
		else
			sel_len = msg_len
		end
		local msg_subtree = tree:add(ch10_canprotocol, buffer(offset, sel_len), "CAN Message #" .. msg_count)
		if tonumber(pinfo.private.pkt_hdr_flag_ts_time_src) == 1 then
			msg_subtree:add_le(buffer(offset+4,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset+4,4):le_uint()))
			msg_subtree:add_le(canfields.ns, buffer(offset,4))
			offset = offset + 4
			msg_subtree:add_le(canfields.s, buffer(offset,4))
			offset = offset + 4
		else
			msg_subtree:add_le(canfields.rtc, buffer(offset,8))
			--msg_subtree:add(rtc_to_localtime(buffer(offset,8)))
			offset = offset + 8
		end
		msg_subtree:add_le(canfields.ipmh, buffer(offset, 4))
		msg_subtree:add_le(canfields.de, buffer(offset,4))
		msg_subtree:add_le(canfields.fe, buffer(offset,4))
		msg_subtree:add_le(canfields.subchannel, buffer(offset,4))
		msg_subtree:add_le(canfields.length, buffer(offset,4))
		local canmsg_len = buffer(offset,1):le_uint() 
		offset = offset + 4
		msg_subtree:add_le(canfields.ipid, buffer(offset, 4))
		msg_subtree:add_le(canfields.busid, buffer(offset,4))
		msg_subtree:add_le(canfields.rtr, buffer(offset,4))
		msg_subtree:add_le(canfields.ide, buffer(offset,4))
		offset = offset + 4
		local remainder = canmsg_len - 4
		msg_subtree:add(buffer(offset, remainder), "Bus Message length=" .. remainder)
		offset = offset + remainder
		if canmsg_len % 2 == 1 then
			msg_subtree:add(buffer(offset, 1), "Padding")
			offset = offset + 1
		end 
	end

end 

--------------
----- COMPutER
--------------


local CH10_COMPUTER_SETUP_FORMAT= {
	[0x0]="ASCII",
	[0x1]="XML",
}
local CH10_COMPUTER_SRCC_FORMAT= {
	[0x0]="Not Changed",
	[0x1]="Changed",
}
local CH10_RCCVRR= {
	[0x7]="IRIG 106-07",
	[0x8]="IRIG 106-09",
	[0x9]="IRIG 106-11",
	[0xA]="IRIG 106-13",
	[0xB]="IRIG 106-15",
	[0xC]="IRIG 106-17",
	[0xD]="IRIG 106-19",
	[0xE]="IRIG 106-22",
}
ch10_computer1_protocol =  Proto("ch10computer", "Ch10 Computer Generated Format 1")
local f = ch10_computer1_protocol.fields
f.cswd_setup = ProtoField.uint32("ch10.computer.format", "Computer Setup Format", base.HEX, CH10_COMPUTER_SETUP_FORMAT, 0x200)
f.cswd_srcc = ProtoField.uint32("ch10.computer.srcc", "Computer Setup Change", base.HEX, CH10_COMPUTER_SRCC_FORMAT, 0x100)
f.cswd_rccver = ProtoField.uint32("ch10.computer.rccver", "Computer Setup Version", base.HEX, CH10_COMPUTER_SRCC_FORMAT, 0xFF)

function ch10_computer1_protocol.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "CH10 - Computer Gen"
	offset = 0
	tree:add_le(f.cswd_setup, buffer(offset,4))
	tree:add_le(f.cswd_srcc, buffer(offset,4))
	tree:add_le(f.cswd_rccver, buffer(offset,4))
	offset = offset + 4
	tree:add(buffer(offset),"Setup File")

end 


ch10_arincprotocol =  Proto("ch10arinc", "Ch10 ARINC-429")
f_ch10arincmsgcount = ProtoField.uint16("ch10.arincmsgcount","Ch10 ARINC MsgCount",base.DEC)
f_ch10arincgap = ProtoField.uint32("ch10.arincgap","Ch10 ARINC Gap Time",base.DEC)
f_ch10arincflag = ProtoField.uint8("ch10.arincflag","Ch10 ARINC Flag",base.DEC)
f_ch10arincbus = ProtoField.uint8("ch10.arincbus","Ch10 ARINC Bus",base.DEC)

ch10_arincprotocol.fields = {f_ch10arincmsgcount, f_ch10arincgap, f_ch10arincflag, f_ch10arincbus}


function ch10_arincprotocol.dissector(buffer, pinfo, tree)

	pinfo.cols.protocol = "CH10 - ARINC"
	local v_buf_len = buffer:len()
    local offset=0
    tree:add_le(f_ch10arincmsgcount, buffer(offset,2))
	local arinc_msg_count = buffer(offset,2):le_uint()
    offset = offset + 4

	for arinc_count = 1, arinc_msg_count, 1
	do
		local arinc_subtree = tree:add(ch10_arincprotocol, buffer(offset, 8), "ARINC Packet " .. arinc_count)
		local v_gap = buffer(offset,3):le_uint() % 0x100000
		arinc_subtree:add_le(f_ch10arincgap, buffer(offset,3), v_gap)
		offset = offset + 2
		local v_flag = buffer(offset,1):uint() / 16
		arinc_subtree:add(f_ch10arincflag, buffer(offset,1), v_flag)
		offset = offset + 1
		arinc_subtree:add(f_ch10arincbus, buffer(offset,1))
		offset = offset + 1
		
		pinfo.private.arinc_le = 1
		msgdissector = Dissector.get("arinc429")
		msgdissector:call(buffer(offset, 4):tvb(), pinfo, arinc_subtree)
		
		--arinc_subtree:add(buffer(offset,4), "Data: " .. buffer(offset,4))
		--local parity = buffer(offset,1):uint() / 128
		--local ssm = buffer(offset,1):uint()/32 % 4
		--local data = ((buffer(offset,1):uint() % 32) * 256 + buffer(offset+1,1):uint() ) * 64 + (buffer(offset+2,1):uint() / 4)
		--local sdi = buffer(offset+2,1):uint() % 4
		--local label = reverse_byte_bit_order(buffer(offset+3,1):uint()+1)
		--arinc_subtree:add(buffer(offset,4),  string.format(" Label: 0o%03o Par:%#01x SSM:%#01x Data:%#05x SDI:%#01x", label, parity, ssm, data, sdi))
		offset = offset + 4

	end
	
end


ch10_uartprotocol =  Proto("ch10uart", "Ch10 UART")
f_ch10uartiph = ProtoField.uint32("ch10uart.uartiphts","Ch10 UART ChannelSpecific",base.HEX)
f_ch10uartiphts_ns = ProtoField.uint64("ch10uart.timestamp_ns","TimeStamp (ns)",base.DEC)
f_ch10uartiphts_s = ProtoField.uint64("ch10uart.timestamp_s","TimeStamp (s)",base.DEC)
f_ch10uartiphs_rtc = ProtoField.uint64("ch10uart.rtc","Relative Time Counter",base.DEC)
f_ch10uartdatalen = ProtoField.uint32("ch10.uartdatalen","Ch10 UART Data Length",base.DEC)
f_ch10uartsubchannel = ProtoField.uint32("ch10.uartsubchannel","Ch10 UART Subchannel",base.DEC)
f_ch10uartpe = ProtoField.uint32("ch10.uartpe","Ch10 UART Parity Error",base.BOOL)

ch10_uartprotocol.fields = {f_ch10uartiph,f_ch10uartiphs_rtc, f_ch10uartiphts_s, f_ch10uartiphts_ns, f_ch10uartdatalen, f_ch10uartsubchannel, f_ch10uartpe}



function ch10_uartprotocol.dissector(buffer, pinfo, tree)

	pinfo.cols.protocol = "CH10 - UART"
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
			if tonumber(pinfo.private.pkt_hdr_flag_ts_time_src) == 1 then
				uart_subtree:add_le(buffer(offset+4,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset+4,4):le_uint()))
				uart_subtree:add_le(f_ch10uartiphts_ns, buffer(offset,4))
				offset = offset + 4
				uart_subtree:add_le(f_ch10uartiphts_s, buffer(offset,4))
				offset = offset + 4
			else
				uart_subtree:add_le(f_ch10uartiphs_rtc, buffer(offset,6))
				--uart_subtree:add(rtc_to_localtime(buffer(offset,6)))
				offset = offset + 8
			end
		end

		v_ch10uartdatalen = buffer(offset,2):le_uint()
		if v_ch10uartdatalen == 0 then
			uart_subtree:add_expert_info(PI_MALFORMED,PI_WARN)
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

--ch10_pcmprotocol.prefs.bytesperminorframe =  Pref.uint( "Bytes per Minor Frame", 0, "Bytes per Minor Frame" )
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
fs.rtc = ProtoField.uint64("ch10pcm.rtc","Relative Time Counter",base.DEC)

fs.datahdr = ProtoField.uint32("ch10pcm.datahdr","Data Header",base.HEX)
fs.datahdr_minor_frame = ProtoField.uint16("ch10pcm.datahdr.minorlck","Minor Frame Status", base.HEX, CH10_DATAHDR_MINOR_FRAME_STATUS, 0xC000)
fs.datahdr_major_frame = ProtoField.uint16("ch10pcm.datahdr.majorlck","Major Frame Status", base.HEX, CH10_DATAHDR_MAJOR_FRAME_STATUS, 0x3000)

function find_word_offsets(buffer, word_size, target_word)
	local offsets = {}
	for offset = 0, buffer:len() - word_size do
		local word = buffer(offset, word_size):uint()
		if word == target_word then
			table.insert(offsets, offset)
		end
	end
	
	return offsets
end

function ch10_pcmprotocol.dissector(buffer, pinfo, tree)

	pinfo.cols.protocol = "CH10 - PCM"
	local v_buf_len = buffer:len()
    local offset=0
    local alignment_32b = bit32.band(bit32.rshift(buffer(offset,4):le_uint(), 21), 0x1)  -- 0 = 16b 1 = 32b
    local minor_frame_lock = bit32.band(bit32.rshift(buffer(offset,4):le_uint(), 28), 0x1)
	
	local data_hdr_len = 2
	if alignment_32b == 1 then
		data_hdr_len = 4
	end
	
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
	local iph_present = math.floor(buffer(offset,4):le_uint()/ (2^30))
	tree:add(buffer(offset,4), "IPH Present= " .. iph_present)
	offset = offset + 4
	local minor_frame_count = 1
	local pcm_payload_len = v_buf_len - 4
	local padding = 0

	if  minor_frame_lock == 0x1  then
	
		-- try and find the sync words
		local sync_bigendian = 0xFE6B2840
		local sync_littleedian = 0x6bfe4028
		offsets = find_word_offsets(buffer, 4, sync_bigendian)
		if #offsets == 0 then
			offsets = find_word_offsets(buffer, 4, sync_littleedian)
		end
		if #offsets > 1 then
			pcm_payload_len = offsets[2] - offsets[1]
		end
		if #offsets >0 then
			minor_frame_count = #offsets
		end
		for _, syncoffset in ipairs(offsets) do
			tree:add(buffer(syncoffset, 4), "Offset: " ..syncoffset)
		end
	end
	if pcm_payload_len % 2 ~= 0 then
		pcm_payload_len = pcm_payload_len + 1
		padding = 1
	end 
	minor_frame_buffer_len = 0

	for minor_frame = 1,minor_frame_count,1 
	do
		local minorframetree = tree:add(buffer(offset, pcm_payload_len), "PCM Minor Frame #" .. minor_frame .. " lock= " .. minor_frame_lock)
		if iph_present == 1.0 then
			if tonumber(pinfo.private.pkt_hdr_flag_ts_time_src) == 1 then
				minorframetree:add_le(buffer(offset+4,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset+4,4):le_uint()))
				minorframetree:add_le(fs.timestampns, buffer(offset,4))
				offset = offset + 4
				minorframetree:add_le(fs.timestamps, buffer(offset,4))
				offset = offset + 4
			else
				minorframetree:add_le(fs.rtc, buffer(offset,8))
				--rtc_upper = buffer(offset+4,2):le_uint()
				--rtc_time = buffer(offset,4):le_uint() + rtc_upper*4294967296
				--minorframetree:add("rtctime=" .. rtc_time)
				--minorframetree:add(rtc_to_localtime(buffer(offset,8)))
				offset = offset + 8
			end

			minorframetree:add_le(fs.datahdr_minor_frame, buffer(offset,data_hdr_len))
			minorframetree:add_le(fs.datahdr_major_frame, buffer(offset,data_hdr_len))
			offset = offset + data_hdr_len
			minor_frame_buffer_len = pcm_payload_len - 10
		end

		local datatree = minorframetree:add(buffer(offset, minor_frame_buffer_len), "Data. Length=".. minor_frame_buffer_len .. " bytes")
		datatree:add(buffer(offset, minor_frame_buffer_len-padding),   "DATA")
		if padding > 0 then
			datatree:add(buffer(offset+minor_frame_buffer_len-padding-10, padding),   "Padding")
		end 
		offset = offset + minor_frame_buffer_len
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

	pinfo.cols.protocol = "CH10 - MILSTD1553"
	local v_buf_len = buffer:len()
    local offset=0
    tree:add_le(f_ch101553iph, buffer(offset,4))
    tree:add_le(f_ch101553msgcount, buffer(offset,4))
    tree:add_le(f_ch10155ttb, buffer(offset,4))
	offset = offset + 4
	msg_count = 0
	mil_dissector =  Dissector.get("milstd1553_le")
	repeat 
		--local v_block_len = buffer(offset+12,2):le_uint() + 12 -- jump to length word
		local msgsubtree = tree:add(ch10_1553protocol, buffer(offset, 2), "MIL-STD-1553 Packet " .. msg_count)
		if tonumber(pinfo.private.pkt_hdr_flag_ts_time_src) == 1 then
			msgsubtree:add_le(buffer(offset+4,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset+4,4):le_uint()))
			msgsubtree:add_le(fs.timestampns, buffer(offset,4))
			offset = offset + 4
			msgsubtree:add_le(fs.timestamps, buffer(offset,4))
			offset = offset + 4
		else
			msgsubtree:add_le(fs.rtc, buffer(offset,8))
			--msgsubtree:add(rtc_to_localtime(buffer(offset,8)))
			offset = offset + 8
		end

		msgsubtree:add_le(f_ch101553bsw, buffer(offset,2))
		offset = offset + 2
		msgsubtree:add_le(f_ch101553gtw, buffer(offset,2))
		offset = offset + 2
		msgsubtree:add_le(f_ch101553length, buffer(offset,2))
		local v_length_message = buffer(offset,2):le_uint()
		offset = offset + 2
		
		local transaction_tree = msgsubtree:add(buffer(offset, v_length_message), "Transaction")
		msgdissector = Dissector.get("milstd1553_le")
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
local COMPUTER_GEN_FMT1_TYPE = 0x1
local ANALOG_DATA_TYPE = 0x21
local CAN_DATA_TYPE = 0x78
local VIDEO_FMT0_DATA_TYPE = 0x40
local VIDEO_FMT1_DATA_TYPE = 0x41
local VIDEO_FMT2_DATA_TYPE = 0x42

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
                              [0x6F]="Ethernet Data, Format 7 (Reserved for future use)",
                              [0x78]="Controller Area Network Bus Data Packet, Format 0"
							  }

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
f.f_ch10rtc = ProtoField.uint64("ch10.rtc","Relative Time Counter",base.DEC)
--f.f_ch10rtc_upr = ProtoField.uint16("ch10.rtcupr","RTC Upr",base.HEX)
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
	local v_ch10datalen = buffer(offset,4):le_uint()
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
	pinfo.private.pkt_hdr_flag_ts_time_src = math.floor(buffer(offset, 1):uint() / 64) % 2
	local pkt_checksum_length_bytes = math.floor(buffer(offset, 1):uint()) % 4
	if pkt_checksum_length_bytes == 3 then
		pkt_checksum_length_bytes = 4
	end 
	--tree:add(buffer(offset, 1), "pkt_hdr_flag_ts_time_src=" .. pinfo.private.pkt_hdr_flag_ts_time_src)
	tree_pkt_hdr_flags:add(f.pkt_hdr_flag_time_sync_err, buffer(offset, 1))
	tree_pkt_hdr_flags:add(f.pkt_hdr_flag_ovf_err, buffer(offset, 1))
	tree_pkt_hdr_flags:add(f.pkt_hdr_flag_time_fmt, buffer(offset, 1))
	tree_pkt_hdr_flags:add(f.pkt_hdr_flag_chksm, buffer(offset, 1))
	
	local v_flag = buffer(offset,1):le_uint()
	offset = offset + 1
	primary_header_tree:add_le(f.f_ch10datatype,buffer(offset,1))
	local v_data_type =  buffer(offset,1):le_uint()
	offset = offset + 1
	primary_header_tree:add_le(f.f_ch10rtc,buffer(offset,6))
	--primary_header_tree:add(rtc_to_localtime(buffer(offset,6)))
	--rtc_upper = buffer(offset+4,2):le_uint()
	--rtc_time = buffer(offset,4):le_uint() + rtc_upper*4294967296
	--primary_header_tree:add("rtctime=" .. rtc_time)
	--primary_header_tree:add(rtc_to_localtime(rtc_time))
	--tree:add(buffer(offset, 2), "offset=" .. offset)
	offset = offset + 6

	--primary_header_tree:add_le(f.f_ch10rtc_upr,buffer(offset,2))
	--offset = offset + 2
	
	primary_header_tree:add_le(f.f_ch10checksum,buffer(offset,2))
	checksum_ok, expected_value = ch10_checksum_validate(buffer(0, offset), buffer(offset,2):le_uint(), tree)
	if not checksum_ok then
		primary_header_tree:add(buffer(offset, 2), string.format("Checksum Wrong. Expected=0x%x", expected_value))
		primary_header_tree:add_expert_info(PI_CHECKSUM,PI_WARN)
	else
		primary_header_tree:add(buffer(offset, 2), string.format("...Checksum Validated"))
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

	remaining_length = buffer(offset):len() - pkt_checksum_length_bytes
	if remaining_length == v_ch10datalen then
		length_warning_message = ""
	else
		length_warning_message = " data length header " .. v_ch10datalen .. " does not match bytes remaining " .. remaining_length 
	end
	
	if v_data_type == ARINC_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "ARINC")
		ch10arinc_pay = Dissector.get("ch10arinc")
		ch10arinc_pay:call(buffer(offset,remaining_length):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == UART_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "UART" .. length_warning_message)
		if remaining_length ~= v_ch10datalen then
			ch10pay_subtree:add_expert_info(PI_MALFORMED,PI_WARN)
		end
		ch10uart_pay = Dissector.get("ch10uart")
		ch10uart_pay:call(buffer(offset,remaining_length):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == TIME1_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "Time Format 1")
		ch10time_pay = Dissector.get("ch10time1")
		ch10time_pay:call(buffer(offset,remaining_length):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == TIME2_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "Time Format 2")
		ch10time2_pay = Dissector.get("ch10time2")
		ch10time2_pay:call(buffer(offset,remaining_length):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == PCM_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "PCM")
		ch10pcm_pay = Dissector.get("ch10pcm")
		ch10pcm_pay:call(buffer(offset,remaining_length):tvb(), pinfo, ch10pay_subtree)
	elseif  v_data_type == MIL_STD_1553_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "MIL-STD-1553")
		ch101553_pay = Dissector.get("ch10_1553")
		ch101553_pay:call(buffer(offset,remaining_length):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == COMPUTER_GEN_FMT1_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "Computer Generated Data Format 1")
		ch10setup_pay = Dissector.get("ch10computer")
		ch10setup_pay:call(buffer(offset,remaining_length):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == ANALOG_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "Analog Data Format 1")
		ch10setup_pay = Dissector.get("ch10analogfmt1")
		ch10setup_pay:call(buffer(offset,remaining_length):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == CAN_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "CAN Data Format 0")
		ch10setup_pay = Dissector.get("ch10can")
		ch10setup_pay:call(buffer(offset,remaining_length):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == VIDEO_FMT0_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "Video Format 0")
		ch10video0_pay = Dissector.get("ch10video0")
		ch10video0_pay:call(buffer(offset,remaining_length):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == VIDEO_FMT2_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "Video Format 2")
		ch10video2_pay = Dissector.get("ch10video2")
		ch10video2_pay:call(buffer(offset,remaining_length):tvb(),pinfo,ch10pay_subtree)
	else
		local data_subtree = tree:add(ch10_protocol, buffer(offset,remaining_length), "Data")
	end
	if pkt_checksum_length_bytes > 0 then
		tree:add(buffer(offset+remaining_length, pkt_checksum_length_bytes), "Checksum")
	end


end


local CH10UTH_MSG_TYPE_VALS = { [0x0]="Full",
                                [0x1]="Segment" }
								
ch10udp_seg_protocol = Proto("ch10UDP", "Chapter 10 UDP")

f_ch10udp_format = ProtoField.uint8("ch10UDP.format", "Format",base.DEC, nil, 0x0F)
f_ch10udp_type   = ProtoField.uint8("ch10UDP.type",   "Type",  base.DEC, CH10UTH_MSG_TYPE_VALS, 0xF0)

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

f_ch10udp_is_segmented = ProtoField.uint32("ch10UDP.segmented","SegmentedPacket",base.HEX)
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
	--ch10_top_subtree:add(buffer(offset,4), "fmt2=" .. v_ch10_format_2_expected .. "len=" .. v_ch10_format_2_exp_len)
	
	if v_ch10_format_2_expected == 2 and v_ch10_format_2_exp_len == v_buffer_len-12 then
		ch10_top_subtree:add(f_ch10udp_type, buffer(offset+3,1))
		ch10_top_subtree:add(f_ch10udp_format, buffer(offset+3,1))		
		v_ch10_type = bit32.extract(buffer(offset,4):uint(),4,4)
		
	else
		--ch10_top_subtree:add(buffer(offset,4), v_ch10_format_2_expected)
		ch10_top_subtree:add(f_ch10udp_format, buffer(offset,4), v_ch10_format)
		v_ch10_type = bit32.extract(buffer(offset,4):le_uint(),4,4)
		
		ch10_top_subtree:add(f_ch10udp_type, buffer(offset,4), v_ch10_type)
		offset = offset + 1  
	end 
	  
    if v_ch10_format_2_expected == 2  and v_ch10_format_2_exp_len == v_buffer_len-12 then  -- and v_ch10_format_2_exp_len == v_buffer_len-12
		ch10_top_subtree:add(f_ch10udp_udpsequence,buffer(offset,3))
		offset = offset + 4
		v_segmentoffset = buffer(offset,1):uint() * 65536
		offset = offset + 1	
		ch10_top_subtree:add(f_ch10udp_pktsize, buffer(offset, 3)) 
        offset = offset + 3
		v_segmentoffset = v_segmentoffset + buffer(offset, 2):uint()
		ch10_top_subtree:add(f_ch10udp_segoffset, buffer(offset, 2), v_segmentoffset)
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
		if v_segmentoffset == 0 then
			ch10_top_subtree:add_le(f_ch10udp_is_segmented, buffer(offset, 4), 0)
		else
			ch10_top_subtree:add_le(f_ch10udp_is_segmented, buffer(offset, 4), 1)
		end
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
	
    if v_segmentoffset == 0  then
		local ch10pay_subtree = tree:add(ch10udp_seg_protocol,buffer(offset),"Ch10 Protocol Data")
		ch10_pay = Dissector.get("ch10")
		ch10_pay:call(buffer(offset):tvb(),pinfo,ch10pay_subtree)
	else
		ch10_top_subtree:add(buffer(offset), string.format("Continuation of segmented packet"))
	end 
    
end

local function heuristic_checker(buffer, pinfo, tree)
    -- guard for length
    local length = buffer:len()
    if length < 28 then return false end

    local ch10_format_le = buffer(0,4):le_uint()
    local ch10_format = buffer(0,4):uint()
	local format = bit32.band(ch10_format_le, 0xFF)
	if format > 3 or format < 1 then return false end
	if format == 1 then
		local sync_wd = buffer(4,2):le_uint()
		if sync_wd ~= 0xeb25 then return false end
	elseif format == 2 then
		local sync_wd = buffer(12,2):le_uint()
		if sync_wd ~= 0xeb25 then return false end
	elseif format == 3 then
		local sync_wd = buffer(8,2):le_uint()
		if sync_wd ~= 0xeb25 then return false end
	end

	ch10udp_seg_protocol.dissector(buffer, pinfo, tree)
	return true
end
ch10udp_seg_protocol:register_heuristic("udp", heuristic_checker)

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
udp_table:add_for_decode_as(ch10udp_seg_protocol)