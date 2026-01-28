
tmns =  Proto("tmnsmessage", "IRIG106 Chapter 24 TmNSMessage")
local hdr = tmns.fields

local EndOfData = {
	[0x0]="Normal",
	[0x1]="End",
}
local DataSourceHealthFlag = {
	[0x0]="No Error",
	[0x1]="Error",
}
local DataSourceTimeLockFlag = {
	[0x0]="Locked",
	[0x1]="Not Locked",
}
local DataSourceAcquiredDataFlag = {
	[0x0]="Acquired",
	[0x1]="Simulated",
}
local MessageFragmentationFlags = {
	[0x0]="Complete",
	[0x1]="First",
	[0x2]="Middle",
	[0x3]="Last",
}
local PlaybackDataFlag = {
	[0x0]="Live",
	[0x1]="Playback",
}
local StandardPackageHeaderFlag = {
	[0x0]="Standard",
	[0x1]="Non Standard",
}
local fields = tmns.fields
fields.endofdata = ProtoField.uint16("tmnsmessage.flag.endofdata","End Of Data", base.HEX, EndOfData, 0x1)
fields.health = ProtoField.uint16("tmnsmessage.flag.health","Health", base.HEX, DataSourceHealthFlag, 0x2)
fields.timelock = ProtoField.uint16("tmnsmessage.flag.timelock","Timelock", base.HEX, DataSourceTimeLockFlag, 0x4)
fields.acquired = ProtoField.uint16("tmnsmessage.flag.acquired","Acquired", base.HEX, DataSourceAcquiredDataFlag, 0x8)
fields.fragmentation = ProtoField.uint16("tmnsmessage.flag.fragmentation","Fragmentation", base.HEX, MessageFragmentationFlags, 0x30)
fields.playback = ProtoField.uint16("tmnsmessage.flag.playback","Playback", base.HEX, PlaybackDataFlag, 0x40)
fields.standard = ProtoField.uint16("tmnsmessage.flag.standard","Playback", base.HEX, StandardPackageHeaderFlag, 0x80)

fields.type =  ProtoField.uint8("tmnsmessage.type","Message Type", base.HEX, nil, 0xF)
fields.optionwordcount =  ProtoField.uint8("tmnsmessage.optionwordcount","Option Word Count", base.DEC, nil, 0xF)
fields.version =  ProtoField.uint8("tmnsmessage.version","Version", base.DEC, nil, 0xF0)

fields.defintionid =  ProtoField.uint32("tmnsmessage.defintionid","Defintion ID", base.HEX)
fields.sequence =  ProtoField.uint32("tmnsmessage.sequence","Sequence", base.DEC)
fields.length =  ProtoField.uint32("tmnsmessage.lenght","Length", base.DEC)

fields.timestamp =  ProtoField.uint64("tmnsmessage.timestamp","Timestamp", base.DEC)


function tmns.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "IRIG106 Chapter 24 TmNSMessage"
    local mtree = tree:add(ch10udp_seg_protocol,buffer(),"TmNSMessage")
    local subtree = mtree:add(ch10udp_seg_protocol,buffer(),"Header")
	offset = 0
    subtree:add(buffer(offset,2), "Flags")
	subtree:add(fields.endofdata, buffer(offset,2))
	subtree:add(fields.health, buffer(offset,2))
	subtree:add(fields.timelock, buffer(offset,2))
	subtree:add(fields.acquired, buffer(offset,2))
	subtree:add(fields.fragmentation, buffer(offset,2))
	subtree:add(fields.playback, buffer(offset,2))
	subtree:add(fields.standard, buffer(offset,2))
	offset = offset + 2
    subtree:add(buffer(offset,1), "Type")
    subtree:add(fields.type, buffer(offset,1))
    offset = offset + 1
    subtree:add(buffer(offset,2), "Option and Version")
    subtree:add(fields.optionwordcount, buffer(offset,1))
    local v_optionwordcount  = math.fmod(buffer(offset,1):uint(), 16 )
    subtree:add(fields.version, buffer(offset,1))
    offset = offset + 1
    subtree:add(fields.defintionid, buffer(offset,4))
    offset = offset + 4
    subtree:add(fields.sequence, buffer(offset,4))
    offset = offset + 4
    subtree:add(fields.length, buffer(offset,4))
    offset = offset + 4
    subtree:add(fields.timestamp, buffer(offset,8))
    offset = offset + 8
    if v_optionwordcount > 0 then
        subtree:add(buffer(offset, v_optionwordcount*4),   "Application Defined Fields")
        offset = offset + v_optionwordcount*4
    end
    mtree:add(buffer(offset), "Payload")

    
end

udp_table = DissectorTable.get("udp.port")
-- register some ports
udp_table:add(9999, tmns)
udp_table:add_for_decode_as(tmns)