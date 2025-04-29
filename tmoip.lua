
tmoip =  Proto("tmoip", "TMoIO")
local tmoipf = tmoip.fields

local TMOIP_VER = {
	[0x2]="218-20",
}
local TMOIP_PLD = {
	[0x0]="no frame alignment",
	[0x1]="PCM frame aligned, first or only packet",
	[0x2]="DQE frame aligned, first or only packet",
	[0x3]="frame aligned, continuation packet",
}
local TMOIP_MIFSS = {
	[0x0]="Search",
	[0x1]="Check",
	[0x2]="Lock",
	[0x3]="Flywheel",
}
local TMOIP_MAFSS = {
	[0x0]="Search",
	[0x1]="Check",
	[0x2]="Lock",
	[0x3]="Flywheel",
}
local TMOIP_TSR = {
	[0x0]="Universal Coordinated Time",
	[0x1]="International Atomic Time",
}
tmoipf.ver = ProtoField.uint8("tmoip.ver","Version", base.DEC, TMOIP_VER, 0xF)
tmoipf.pld = ProtoField.uint8("tmoip.pld","Payload Type", base.HEX, TMOIP_PLD, 0x30)
tmoipf.minfss = ProtoField.uint8("tmoip.minfss","Minor Frame Search", base.HEX, TMOIP_MIFSS, 0xC0)
tmoipf.majfss = ProtoField.uint8("tmoip.majfss","Minor Frame Search", base.HEX, TMOIP_MAFSS, 0x3)
tmoipf.tss = ProtoField.uint8("tmoip.tss","Timestamp Source Reference", base.HEX, TMOIP_TSR, 0x80)
tmoipf.seq = ProtoField.uint16("tmoip.seq","Sequence", base.DEC)
tmoipf.ptpseconds      = ProtoField.uint32("tmoip.ptpseconds", "PTP Seconds", base.DEC)
tmoipf.ptpnanoseconds  = ProtoField.uint32("tmoip.ptpnanoseconds", "PTP Nanoseconds", base.DEC)

function tmoip.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "TMoIP"
    local ttree = tree:add(buffer(), "TMoIP")
	offset = 0
	ttree:add(tmoipf.ver, buffer(offset,1))
	ttree:add(tmoipf.pld, buffer(offset,1))
	ttree:add(tmoipf.minfss, buffer(offset,1))
    offset = offset + 1
    ttree:add(tmoipf.majfss, buffer(offset,1))
    ttree:add(tmoipf.tss, buffer(offset,1))
    offset = offset + 1
    ttree:add(tmoipf.seq, buffer(offset,2))
    offset = offset + 2
    ttree:add(tmoipf.ptpseconds, buffer(offset,4))
    offset = offset + 4
    ttree:add(tmoipf.ptpnanoseconds, buffer(offset,4))
	
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register some ports
--udp_table:add(4444, inetx_proto)
udp_table:add_for_decode_as(tmoip)