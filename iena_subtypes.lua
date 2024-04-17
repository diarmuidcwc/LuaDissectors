
-------------------------------------------------------
-- This is a Wireshark dissector for the Airbus IENA packet format
-------------------------------------------------------

-- Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuidcwc/LuaDissectors


--------------------------------------------------
-- D-TYPE Messages
-----------------------------------------------
-- declare our protocol
iena_dtype_proto = Proto("iena-d","IENA D-Type")
local dfields = iena_dtype_proto.fields

-- Declare a few fields
dfields.paramid = ProtoField.uint16("ienad.paramid","Param ID",base.HEX)
dfields.delay   = ProtoField.uint16("ienad.delay","Delay",base.DEC)
dfields.data    = ProtoField.bytes("ienad.data","DataWord",base.COLON)

-- what dissector for the payload word
iena_dtype_proto.prefs["worddissector"] = Pref.string("Word Dissector","a429","What dissector to use for the message data")

-- create a function to dissect it
function iena_dtype_proto.dissector(buffer,pinfo,ienad_subtree)
    
    pinfo.cols.protocol = "iena-d" -- the name in the wirshark view
    --local ienad_subtree = tree:add(iena_dtype_proto,buffer(),"IENA-D Message")
    
	local length_buffer = buffer:len()
	local offset=0
    
	ienad_subtree:add(dfields.paramid,buffer(offset,2))
    offset = offset + 2
	ienad_subtree:add(dfields.delay,buffer(offset,2))
    offset = offset + 2
    repeat 
        ienad_subtree:add(dfields.data, buffer(offset,pinfo.private.wordsize))
        
		if iena_dtype_proto.prefs["worddissector"] then
			datadissector = Dissector.get(iena_dtype_proto.prefs["worddissector"])
			datadissector:call(buffer(offset,pinfo.private.wordsize):tvb(),pinfo,ienad_subtree)
		end
		offset = offset + pinfo.private.wordsize
    until offset == length_buffer

end
    
--------------------------------------------------
-- N-TYPE Messages
-----------------------------------------------
-- declare our protocol
iena_ntype_proto = Proto("iena-n","IENA N-Type")
local nfields = iena_ntype_proto.fields

-- Declare a few fields
nfields.paramid = ProtoField.uint16("ienan.paramid","Param ID",base.HEX)
nfields.data    = ProtoField.bytes("ienan.data","DataWord",base.COLON)

-- create a function to dissect it
function iena_ntype_proto.dissector(buffer, pinfo, ienan_subtree)
    
    pinfo.cols.protocol = "iena-n" -- the name in the wirshark view
    
	local length_buffer = buffer:len()    
	local offset=0
    
	ienan_subtree:add(nfields.paramid,buffer(offset,2))
    offset = offset + 2
    repeat 
        ienan_subtree:add(nfields.data,buffer(offset,pinfo.private.wordsize))
        offset = offset + pinfo.private.wordsize
    until offset == length_buffer

end
    
--------------------------------------------------
-- M-TYPE Messages
-----------------------------------------------
-- declare our protocol
iena_mtype_proto = Proto("iena-m","IENA M-Type")
local mfields = iena_mtype_proto.fields

-- Declare a few fields
mfields.paramid = ProtoField.uint16("ienam.paramid","Param ID",base.HEX)
mfields.delay = ProtoField.uint16("ienam.delay","Delay",base.DEC)
mfields.length = ProtoField.uint16("ienam.length","Length",base.DEC)
mfields.data = ProtoField.bytes("ienam.data","DataSet",base.COLON)
mfields.padding = ProtoField.bytes("ienam.padding","Padding",base.NONE)

-- prefs
-- this can be overwritten in the Preference page
iena_mtype_proto.prefs["messagedissector"] = Pref.string("Message Dissector","","What dissector to use for the message data")

-- create a function to dissect it
function iena_mtype_proto.dissector(buffer,pinfo,ienam_subtree)
    
    pinfo.cols.protocol = "iena-m" -- the name in the wirshark view
	local length_buffer = buffer:len()
	local offset=0
    
	ienam_subtree:add(mfields.paramid,buffer(offset,2))
    offset = offset + 2
	ienam_subtree:add(mfields.delay,buffer(offset,2))
    offset = offset + 2
	ienam_subtree:add(mfields.length,buffer(offset,2))
    local datalen = buffer(offset,2):uint()
    offset = offset + 2
    if iena_mtype_proto.prefs["messagedissector"] ~= '' and datalen > 0 then
        messagedissector = Dissector.get(iena_mtype_proto.prefs["messagedissector"])
        messagedissector:call(buffer(offset, datalen):tvb(), pinfo, ienam_subtree)
	elseif datalen > 0 then
		ienam_subtree:add(mfields.data, buffer(offset,datalen))
	else
		ienam_subtree:add(buffer(offset-2,2), "Length field of 0 is illegal")
		ienam_subtree:add_expert_info(PI_PROTOCOL,PI_WARN)
    end
	offset = offset + datalen
	-- Optional padding
	if datalen % 2 == 1 then
		ienam_subtree:add(mfields.padding, buffer(offset,1))
		return datalen + 6 + 1
	else
		return datalen + 6
	end
end

--------------------------------------------------
-- Q-TYPE Messages
-----------------------------------------------
-- declare our protocol
iena_qtype_proto = Proto("iena-q","IENA Q-Type")
local qfields = iena_qtype_proto.fields

-- Declare a few fields
qfields.paramid = ProtoField.uint16("ienaq.paramid","Param ID",base.HEX)
qfields.length = ProtoField.uint16("ienaq.length","Length",base.DEC)
qfields.data = ProtoField.bytes("ienaq.data","DataSet",base.COLON)
qfields.padding = ProtoField.bytes("ienaq.padding","Padding",base.COLON)

-- prefs
-- this can be overwritten in the Preference page
iena_qtype_proto.prefs["messagedissector"] = Pref.string("Message Dissector","","What dissector to use for the message data")

-- create a function to dissect it
function iena_qtype_proto.dissector(buffer,pinfo,tree)
    
    pinfo.cols.protocol = "iena-q" -- the name in the wirshark view
    local ienaq_subtree = tree:add(iena_qtype_proto,buffer(),"IENA-Q Message")
	local length_buffer = buffer:len()
	local offset=0
    
	ienaq_subtree:add(qfields.paramid,buffer(offset,2))
    offset = offset + 2
	ienaq_subtree:add(qfields.length,buffer(offset,2))
    local datalen = buffer(offset,2):uint()
    offset = offset + 2
    if iena_qtype_proto.prefs["messagedissector"] ~= '' and datalen > 0 then
        messagedissector = Dissector.get(iena_qtype_proto.prefs["messagedissector"])
        messagedissector:call(buffer(offset, datalen):tvb(), pinfo, ienaq_subtree)
	elseif datalen > 0 then
		ienaq_subtree:add(qfields.data, buffer(offset,datalen))
	else
		ienaq_subtree:add(buffer(offset-2,2), "Length field of 0 is illegal")
		ienaq_subtree:add_expert_info(PI_PROTOCOL,PI_WARN)
    
    end
	offset = offset + datalen
	-- Optional padding
	if datalen % 2 == 1 then
		ienaq_subtree:add(qfields.padding, buffer(offset,1))
		return datalen + 4 + 1
	else
		return datalen + 4
	end
end

--------------------------------------------------
-- P-TYPE Messages
-----------------------------------------------
-- declare our protocol
iena_ptype_proto = Proto("iena-p","IENA P-Type")
local pfields = iena_ptype_proto.fields

-- the preferences
iena_ptype_proto.prefs["messages_per_pattern"] = Pref.uint("Messages Per Pattern",2,"Number of messages per pattern")

-- create a function to dissect it
function iena_ptype_proto.dissector(buffer,pinfo,tree)
    
    pinfo.cols.protocol = "iena-p" -- the name in the wirshark view
    local ienap_subtree = tree:add(iena_ptype_proto,buffer(),"IENA-P Message")
	local length_buffer = buffer:len()
    local pref_messages_per_pattern = iena_ptype_proto.prefs["messages_per_pattern"]
    local patterns = length_buffer/pref_messages_per_pattern
    local offset = 0
    
    local pattern_count = 1
    while (offset < length_buffer) do
        local pattern_subtree = ienap_subtree:add(buffer(offset,pref_messages_per_pattern),"Pattern " .. pattern_count)
        local word_count = 0
        while ((word_count < pref_messages_per_pattern) and (offset < length_buffer))  do
            pattern_subtree:add(buffer(offset,pinfo.private.wordsize),"Word " .. word_count .. "=".. (buffer(offset,pinfo.private.wordsize)))
            offset = offset + pinfo.private.wordsize
            word_count = word_count + 1
		end	
        pattern_count = pattern_count + 1
	end

end
    
