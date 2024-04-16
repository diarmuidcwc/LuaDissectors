
-------------------------------------------------------
-- This is a basic Wireshark dissector for the MPEG Transport Stream Payload
-------------------------------------------------------

-- Copyright 2014 Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuid
-- https://github.com/diarmuidcwc/LuaDissectors



-- This dissects an MPEG TS Block
mpegts_proto = Proto("mpegts","MPEG2 Transport Stream")
local ifields  = mpegts_proto.fields

-- Declare a few fields that we are in
ifields.syncbyte = ProtoField.uint8("mpegts.sync","SyncByte", base.HEX)
ifields.tei = ProtoField.uint16("mpegts.tei","Transport error indicator", base.HEX, nil, 0x8000)
ifields.pusi = ProtoField.uint16("mpegts.pusi","Payload unit start indicator", base.HEX, nil, 0x4000)
ifields.tp = ProtoField.uint16("mpegts.tp","Transport Priority", base.HEX, nil, 0x2000)
ifields.pid = ProtoField.uint16("mpegts.pid", "PID", base.HEX,nil, 0x1FFF)
ifields.payload = ProtoField.bytes("mpegts.payload", "Payload", base.DOT)

local TSC_FIELD = {
	[0x0] = "Not Scrambled",
	[0x1] = "Reserved for future use",
	[0x2] = "Scrambled with even key",
	[0x3] = "Scrambled with odd key"
}
ifields.tsc = ProtoField.uint8("mpegts.tsc","Transport scrambling control", base.HEX, TSC_FIELD, 0xc0)

local AFC_FIELD = {
	[0x0] = "Reserved",
	[0x1] = "no adaptation field, payload only",
	[0x2] = "adaptation field only, no payload",
	[0x3] = "adaptation field followed by payload"
}
ifields.afc = ProtoField.uint8("mpegts.afc","Adaptation field control", base.HEX, AFC_FIELD, 0x30)
ifields.continuity = ProtoField.uint8("mpegts.continuity","Continuity",base.DEC, nil, 0xf)


-- create a function to dissect it
function mpegts_proto.dissector(buffer,pinfo,tree)
	--local datasubtree = tree:add(bcutemperature_proto,buffer(),"BCU Temperature")	
	local buf_len = buffer:len()
	offset = 0
	tree:add(ifields.syncbyte, buffer(offset,1))
	offset = offset + 1
	tree:add(ifields.tei, buffer(offset,2))
	tree:add(ifields.pusi, buffer(offset,2))
	tree:add(ifields.tp, buffer(offset,2))
	tree:add(ifields.pid, buffer(offset,2))
	offset = offset + 2
	tree:add(ifields.tsc, buffer(offset,1))
	tree:add(ifields.afc, buffer(offset,1))
	tree:add(ifields.continuity, buffer(offset,1))
	offset = offset + 1
	tree:add(ifields.payload, buffer(offset,buf_len-offset))
end