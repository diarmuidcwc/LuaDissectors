
-------------------------------------------------------
-- This is a Wireshark dissector for the Airbus IENA packet format
-------------------------------------------------------

-- Copyright 2014 Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuidcwc/LuaDissectors


-- some ports of interest
IENA_PORT        = 51000

LXRS_ID = 0xF6Ae

TYPE_P = 0
TYPE_D = 1  -- with delay
TYPE_N = 2
TYPE_M = 3  -- with delay
TYPE_Q = 4
local type_to_txt = {[TYPE_P] = "P-type", [TYPE_D] = "D-type", [TYPE_N]  = "N-type",
	[TYPE_M] = "M-type", [TYPE_Q] = "Q-type"}
-- declare our protocol
iean_proto = Proto("iena","IENA Protocol")
local ifields           = iean_proto.fields

local KS_POS = {[0x0]="Not positional",[0x1]="positional parameters key"}
local KS_DIS = {[0x0]="To be proceeded",[0x1]="To be discarded by the CUB"}
local KS_MSG = {[0x0]="Not message parameters key",[0x1]="Message parameters key"}
local KS_DLY = {[0x0]="Delay field not used",[0x1]="Delay field used"}
local KS_N4 = {[0x0]="N4 equipment may use this key",[0x1]="N4 equipment may not use this key"}

-- Declare a few fields
ifields.ienakey = ProtoField.uint16("iena.key","Key", base.HEX)
ifields.size = ProtoField.uint16("iena.size","Size",base.DEC)
ifields.time = ProtoField.uint64("iena.time","Time",base.DEC, nil, 0xFFFFFFFFFFFF)
ifields.sec = ProtoField.uint32("iena.seconds","Seconds",base.DEC)
ifields.usec = ProtoField.uint32("iena.useconds","MicroSeconds",base.DEC)
ifields.keystatus = ProtoField.uint8("iena.keystatus","Key Status",base.HEX)
ifields.keystatus_pos = ProtoField.uint8("iena.keystatus.positional","Key Status Positional",base.HEX, KS_POS,0x80)
ifields.keystatus_dis = ProtoField.uint8("iena.keystatus.discard","Key Status Discard",base.HEX, KS_DIS,0x40)
ifields.keystatus_msg = ProtoField.uint8("iena.keystatus.message","Key Status Message",base.HEX, KS_MSG,0x20)
ifields.keystatus_dly = ProtoField.uint8("iena.keystatus.delay","Key Status Delay",base.HEX, KS_DLY,0x10)
ifields.keystatus_n4 = ProtoField.uint8("iena.keystatus.n4","Key Status N4",base.HEX, KS_N4,0x8)
ifields.keystatus_wordsize = ProtoField.uint8("iena.keystatus.wordsize","Key Status Word Size",base.DEC,nil,0x7)
ifields.n2status = ProtoField.uint16("iena.n2status","N2 Status",base.HEX)
ifields.sequencenum = ProtoField.uint16("iena.sequencenum","Sequence Number",base.DEC)
ifields.trailer = ProtoField.uint16("iena.trailer","IENA Trailer",base.HEX)


-- create a function to dissect it
function iean_proto.dissector(buffer,pinfo,tree)

    pinfo.cols.protocol = "iena" -- the name in the wirshark view
    local iena_top_subtree = tree:add(iean_proto,buffer(),"IENA Protocol Data")
	-- create a subtree for the IENA Header
	subtree = iena_top_subtree:add(buffer(0,14),"IENA Header")
	local offset=0
	subtree:add(ifields.ienakey,buffer(offset,2))
    local key_id_v = buffer(offset,2):uint()
	offset = offset + 2
	subtree:add(ifields.size,buffer(offset,2))
    local iena_size_in_words = buffer(offset,2):uint()
	offset = offset + 2
	subtree:add(ifields.time,buffer(offset,6))
	local current_year = os.date("*t", os.time()).year
	-- iena time is time since first sec of this year
	-- lua can't handle 6byte integers so first truncate the last 2 bytes and then compensate for that later
	-- probably something lost in the rounding but good enough
	local time_in_usec = buffer(offset,4):uint() -- this is actually usec divided by 2^16
	local ostime_this_year = os.time{year=current_year, month=1, day=1, hour=0, min=0, sec=0} -- get the 1st jan this year
	subtree:add(buffer(offset,6),"Date: " .. os.date("!%H:%M:%S %d %b %Y",(ostime_this_year + time_in_usec/15.2587890625)))
        trunc_sec = buffer(offset+2,4):uint()
        hi_sec = buffer(offset,2):uint() * 4294967296
        totalusec = hi_sec + trunc_sec

    subtree:add(ifields.sec, buffer(offset,6), math.floor(totalusec/1e6))
    subtree:add(ifields.usec, buffer(offset,6), totalusec % 1e6)

	offset = offset + 6
	subtree:add(ifields.keystatus,buffer(offset,1))
	subtree:add(ifields.keystatus_pos,buffer(offset,1))
	subtree:add(ifields.keystatus_dis,buffer(offset,1))
	subtree:add(ifields.keystatus_msg,buffer(offset,1))
	subtree:add(ifields.keystatus_dly,buffer(offset,1))
	subtree:add(ifields.keystatus_n4,buffer(offset,1))
	subtree:add(ifields.keystatus_wordsize,buffer(offset,1))
	local v_keystatus = buffer(offset,1):uint()
	local is_positional = bit32.band(bit32.rshift(v_keystatus, 7), 0x1)
	local is_msg = bit32.band(bit32.rshift(v_keystatus, 5), 0x1)
	local has_dly = bit32.band(bit32.rshift(v_keystatus, 4), 0x1)
	local v_data_words_n_d = bit32.band(v_keystatus, 0x7)
	pinfo.private.wordsize = v_data_words_n_d

	local packet_type = TYPE_P
	if is_positional == 0 and is_msg == 1 then
		if has_dly == 1 then
			packet_type = TYPE_M
		else
			packet_type = TYPE_Q
		end
	elseif is_msg == 0  then
		if has_dly == 1 then
			packet_type = TYPE_D
		else
			packet_type = TYPE_N
		end
	else
		packet_type = TYPE_P
	end

	subtree:add(buffer(offset, 1), type_to_txt[packet_type] .. " Wordsize=" .. v_data_words_n_d)
	offset = offset + 1
	subtree:add(ifields.n2status,buffer(offset,1))
	offset = offset + 1
	subtree:add(ifields.sequencenum,buffer(offset,2))
	offset = offset + 2
	
	local payload_len_b = iena_size_in_words*2-16
        
    -- IENA- N Messages
    if (packet_type == TYPE_N) then
        local n_len_bytes = (v_data_words_n_d + 1) * 2 -- ParamID
        local n_instances = payload_len_b / n_len_bytes
        -- keystatus field contain the number of D words so calculate the lenght of IENA-N message from that
        for nmessage= 1, n_instances do
            ienan_subtree = iena_top_subtree:add(buffer(offset, n_len_bytes),"IENA-N Message #" .. nmessage)
            ienandiss = Dissector.get("iena-n")
            ienandiss:call(buffer(offset,n_len_bytes):tvb(), pinfo, ienan_subtree)
            offset = offset + n_len_bytes
        end
    elseif (packet_type == TYPE_D) then
        d_len_bytes = (v_data_words_n_d + 2) * 2 -- ParamID + Delat
        d_instances = (iena_size_in_words * 2 - 14 - 2) / d_len_bytes
        -- keystatus field contain the number of D words so calculate the lenght of IENA-D message from that
        for dmessage= 1, d_instances do
            ienad_subtree = iena_top_subtree:add(buffer(offset,d_len_bytes),"IENA-D Message #" .. dmessage .. " " .. d_instances)
            ienaddiss = Dissector.get("iena-d")
            ienaddiss:call(buffer(offset,d_len_bytes):tvb(),pinfo,ienad_subtree)
            offset = offset + d_len_bytes
        end
    elseif (packet_type == TYPE_M) then
		local m_msg_count = 0
		repeat
			exp_len = buffer(offset+4, 2):uint() + 6
			if exp_len % 2 == 1 then
				exp_len =  exp_len + 1
			else
				exp_len = exp_len
			end
			ienam_subtree = iena_top_subtree:add(buffer(offset, exp_len),"IENA-M Message #" .. m_msg_count)
			ienamdiss = Dissector.get("iena-m")
			consumed = ienamdiss:call(buffer(offset):tvb(), pinfo, ienam_subtree)
			offset = offset + consumed
			m_msg_count = m_msg_count + 1
		until (offset >= iena_size_in_words*2 -2)

    elseif (packet_type == TYPE_Q) then
		local m_msg_count = 0
		repeat
			exp_len = buffer(offset+2, 2):uint() + 4
			if exp_len % 2 == 1 then
				exp_len =  exp_len + 1
			else
				exp_len = exp_len
			end
			--ienaq_subtree = iena_top_subtree:add(buffer(offset, 2),"IENA-Q Message #" .. m_msg_count .. " exp=" .. exp_len .. " len=" .. iena_size_in_words)
			ienaq_subtree = iena_top_subtree:add(buffer(offset, exp_len),"IENA-Q Message #" .. m_msg_count)
			ienaqdiss = Dissector.get("iena-q")
			consumed = ienaqdiss:call(buffer(offset):tvb(), pinfo, ienaq_subtree)
			offset = offset + consumed
			m_msg_count = m_msg_count + 1
		until (offset >= iena_size_in_words*2 -2)


    else
        ienapdissector = Dissector.get("iena-p")
        ienapdissector:call(buffer(offset,iena_size_in_words*2-16):tvb(),pinfo,subtree,4)
        offset = offset + iena_size_in_words*2-22
    end
	-- the trailer
	subtree:add(ifields.trailer,buffer((iena_size_in_words*2)-2,2))
	

  end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register some ports
udp_table:add_for_decode_as(iean_proto)
udp_table:add(IENA_PORT,iean_proto)