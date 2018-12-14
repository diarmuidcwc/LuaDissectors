-------------------------------------------------------
-- This is a Wireshark dissector for the Ch10 packet format
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
dofile(CUSTOM_DISSECTORS.."\\parse_arinc.lua")

CH10_PORT = 6679

UART_DATA_TYPE = 0x50
ARINC_DATA_TYPE = 0x38



function ch10_checksum_validate(buffer, checksum, tree)

	
	local v_len = buffer:len()
	local v_checksum = 0
	local v_offset = 0
	repeat
		v_checksum = (v_checksum + buffer(v_offset,2):le_uint()) % 65536
        tree:add(buffer(v_offset, 2), string.format("Checksum=0x%x Data=0x%x", v_checksum, buffer(v_offset,2):le_uint()))
        v_offset = v_offset + 2
	until v_offset == v_len
	
	if v_checksum  == checksum then
		return true, checksum
	else
		return false, v_checksum
	end

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

ch10_protocol =  Proto("ch10", "Chapter 10")
f_ch10sync = ProtoField.uint16("ch10.sync","Sync",base.HEX)
f_ch10chid = ProtoField.uint16("ch10.id","Channel ID",base.HEX)
f_ch10pktlen = ProtoField.uint32("ch10.pktlen","Packet Len",base.DEC)
f_ch10datalen = ProtoField.uint32("ch10.datalen","Data Len",base.DEC)
f_ch10datatypeversion = ProtoField.uint8("ch10.version","Data Type Version",base.HEX)
f_ch10sequence = ProtoField.uint8("ch10.sequence","Sequence",base.DEC)
f_ch10pktflags = ProtoField.uint8("ch10.pktflag","Packet Flags",base.HEX)
f_ch10datatype = ProtoField.uint8("ch10.datatype","Data Type",base.HEX)
f_ch10rtc_lwr = ProtoField.uint32("ch10.rtclwr","RTC Lwr",base.HEX)
f_ch10rtc_upr = ProtoField.uint16("ch10.rtcupr","RTC Upr",base.HEX)
f_ch10checksum = ProtoField.uint16("ch10.checksum","Checksum",base.HEX)
f_ch10tsns= ProtoField.uint32("ch10.tsns","Timestamp (ns)",base.DEC)
f_ch10tss= ProtoField.uint32("ch10.tss","Timestamp (s)",base.DEC)
f_ch10hdrcs= ProtoField.uint16("ch10.hdrcs","Header Checksum",base.HEX)

ch10_protocol.fields = {f_ch10sync, f_ch10chid, f_ch10pktlen, f_ch10datalen, f_ch10datatypeversion, f_ch10sequence, f_ch10pktflags,
    f_ch10datatype, f_ch10rtc_lwr, f_ch10rtc_upr, f_ch10checksum, f_ch10tsns, f_ch10tss, f_ch10hdrcs}
    
function ch10_protocol.dissector(buffer,pinfo,tree)

    local offset=0
    tree:add_le(f_ch10sync,buffer(offset,2))
    offset = offset + 2
    tree:add_le(f_ch10chid,buffer(offset,2))
    offset = offset + 2
    tree:add_le(f_ch10pktlen,buffer(offset,4))
    offset = offset + 4
    tree:add_le(f_ch10datalen,buffer(offset,4))
    offset = offset + 4
    tree:add_le(f_ch10datatypeversion,buffer(offset,1))
    offset = offset + 1
    tree:add_le(f_ch10sequence,buffer(offset,1))
    offset = offset + 1
    tree:add_le(f_ch10pktflags,buffer(offset,1))
    local v_flag = buffer(offset,1):uint()
    offset = offset + 1
    tree:add_le(f_ch10datatype,buffer(offset,1))
	local v_data_type =  buffer(offset,1):uint()
    offset = offset + 1
    tree:add_le(f_ch10rtc_lwr,buffer(offset,4))
    offset = offset + 4
    tree:add_le(f_ch10rtc_upr,buffer(offset,2))
    offset = offset + 2
    tree:add_le(f_ch10checksum,buffer(offset,2))
	checksum_ok, expected_value = ch10_checksum_validate(buffer(0, offset), buffer(offset,2):le_uint(), tree)
	if not checksum_ok then
		tree:add(buffer(offset, 2), string.format("Checksum Wrong. Expected=0x%x", expected_value))
		tree:add_expert_info(PI_CHECKSUM,PI_WARN)
	end
    offset = offset + 2
    if v_flag / 128 >= 1.0 then
        local sec_hdr = tree:add(ch10_protocol, buffer(offset), "Secondary Header")
        sec_hdr:add_le(f_ch10tsns,buffer(offset,4))
        offset = offset + 4
        sec_hdr:add_le(f_ch10tss,buffer(offset,4))
        offset = offset + 6
        sec_hdr:add_le(f_ch10hdrcs,buffer(offset,2))
		checksum_ok, expected_value = ch10_checksum_validate(buffer(offset-10, 10), buffer(offset,2):le_uint(), tree)
		if not checksum_ok then
			tree:add(buffer(offset, 2), string.format("Checksum Wrong. Expected=0x%x", expected_value))
			tree:add_expert_info(PI_CHECKSUM,PI_WARN)
		end
        offset = offset + 2
    end
	if v_data_type == ARINC_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset), "ARINC")
		ch10arinc_pay = Dissector.get("ch10arinc")
		ch10arinc_pay:call(buffer(offset):tvb(),pinfo,ch10pay_subtree)
	elseif  v_data_type == UART_DATA_TYPE then
		local ch10pay_subtree = tree:add(ch10_protocol, buffer(offset), "UART")
		ch10uart_pay = Dissector.get("ch10uart")
		ch10uart_pay:call(buffer(offset):tvb(),pinfo,ch10pay_subtree)
	else
		local data_subtree = tree:add(ch10_protocol, buffer(offset), "Data")
	end 

end

ch10udp_seg_protocol = Proto("ch10UDP", "Chapter 10 UDP")
f_ch10version_type = ProtoField.uint8("ch10UDP.count","Version",base.HEX)
f_sequence = ProtoField.uint32("ch10UDP.sequence","Sequence",base.DEC)
f_ch10id = ProtoField.uint32("ch10UDP.channelID","Channel ID",base.DEC)
f_ch10sequence = ProtoField.uint32("ch10UDP.ch10sequence","Channel Sequence",base.DEC)
f_segoffset = ProtoField.uint32("ch10UDP.segoffset","Segment Offset",base.DEC)

ch10udp_seg_protocol.fields = {f_ch10version_type, f_sequence, f_ch10id, f_ch10sequence, f_segoffset }



-- create a function to dissect it
function ch10udp_seg_protocol.dissector(buffer,pinfo,tree)

    pinfo.cols.protocol = "Chapter 10" -- the name in the wirshark view
    local ch10_top_subtree = tree:add(ch10udp_seg_protocol,buffer(),"Ch10 UDP Data")
	
	local offset=0
	ch10_top_subtree:add(f_ch10version_type,buffer(offset,1))
    local v_ch10_version = buffer(offset,1):uint() / 16
    --ch10_top_subtree:add(buffer(offset, 1), "v_ch10_version: "..v_ch10_version)
	offset = offset + 1
    ch10_top_subtree:add_le(f_sequence,buffer(offset,3))
    offset = offset + 3
    
    if v_ch10_version >= 1.0 then
        ch10_top_subtree:add_le(f_ch10id,buffer(offset,2))
        offset = offset + 2
        ch10_top_subtree:add_le(f_ch10sequence,buffer(offset,1))
        offset = offset + 2
        ch10_top_subtree:add_le(f_segoffset,buffer(offset,4))
    end
    
    local ch10pay_subtree = tree:add(ch10udp_seg_protocol,buffer(offset),"Ch10 Protocol Data")
    ch10_pay = Dissector.get("ch10")
	ch10_pay:call(buffer(offset):tvb(),pinfo,ch10pay_subtree)
    
end


-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register some ports
udp_table:add(CH10_PORT,ch10udp_seg_protocol)
