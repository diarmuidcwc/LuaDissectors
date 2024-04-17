-------------------------------------------------------
-- This is a Wireshark dissector for the iNet-X packet format
-- http://www.cwc-ae.com/custom/pdfs/White%20Paper_iNET-X_packets.pdf
-------------------------------------------------------

-- Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuidcwc/LuaDissectors



inetx_proto = Proto("inetx", "iNetX Protocol")
-- The pcall is here so that it doesn't throw an exception every time it loads
pcall(function () DissectorTable.heuristic_new("inetx.payload", inetx_proto) end)

local PIF_ERROR = {
	[0x0]="No Data Error",
	[0x1]="Data Error",
}
local PIF_TIMEOUT = {
	[0x0]="Packet Generated Normally",
	[0x1]="Packet Generated after Timeout",
}
-- Declare a few fields
local ifields           = inetx_proto.fields
ifields.inetcontrol     = ProtoField.uint32("inetx.control", "Control", base.HEX)
ifields.streamid        = ProtoField.uint32("inetx.streamid", "StreamID", base.HEX)
ifields.inetsequencenum = ProtoField.uint32("inetx.sequencenum", "Sequence Number", base.DEC)
ifields.packetlen       = ProtoField.uint32("inetx.packetlen", "Packet Length", base.DEC)
ifields.ptpseconds      = ProtoField.uint32("inetx.ptpseconds", "PTP Seconds", base.DEC)
ifields.ptpnanoseconds  = ProtoField.uint32("inetx.ptpnanoseconds", "PTP Nanoseconds", base.DEC)

ifields.pif             = ProtoField.uint32("inetx.pif.error", "PIF Error", base.HEX)
ifields.piferr          = ProtoField.uint32("inetx.pif.error", "PIF Error", base.HEX, PIF_ERROR, 0x80000000)
ifields.piflostcount    = ProtoField.uint32("inetx.pif.lost", "PIF Lost Count", base.DEC, nil, 0x78000000)
ifields.piftimeout      = ProtoField.uint32("inetx.pif.timeout", "PIF Timeout", base.HEX, PIF_TIMEOUT, 0x04000000)

ifields.inetxerrorbit   = ProtoField.uint32("inetx.EB", "EB", base.HEX)
ifields.inetxlostcount  = ProtoField.uint32("inetx.lostcout", "Lost Count", base.DEC)
ifields.inetxtimeout    = ProtoField.uint32("inetx.TO", "Timeout", base.HEX)
ifields.payload         = ProtoField.bytes("inetx.payload", "Payload", base.DOT)


-- create a function to dissect it


function inetx_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "inetx"
    local iNetX_top_subtree = tree:add(buffer(), "iNet-X")

    -- The iNet-X Header Definition
    local hdr_subtree = iNetX_top_subtree:add(buffer(0, 28), "iNetX Header")
    local offset = 0

    hdr_subtree:add(ifields.inetcontrol, buffer(offset, 4))
    offset = offset + 4

    hdr_subtree:add(ifields.streamid, buffer(offset, 4))
    offset = offset + 4

    hdr_subtree:add(ifields.inetsequencenum, buffer(offset, 4))
    offset = offset + 4

    hdr_subtree:add(ifields.packetlen, buffer(offset, 4))
    local iNetX_payloadsize_in_bytes = buffer(offset, 4):uint() - 28
    offset = offset + 4

    local ptptimesubtree = hdr_subtree:add(buffer(offset, 8), "PTPTimeStamp")
    ptptimesubtree:add(buffer(offset, 4), "Date: " .. os.date("!%H:%M:%S %d %b %Y", buffer(offset, 4):uint()))
    ptptimesubtree:add(ifields.ptpseconds, buffer(offset, 4))
    offset = offset + 4

    ptptimesubtree:add(ifields.ptpnanoseconds, buffer(offset, 4))
    offset = offset + 4

    local pifsubtree = hdr_subtree:add(buffer(offset, 4), "PIF")
    pifsubtree:add(ifields.piferr, buffer(offset, 4))
    pifsubtree:add(ifields.piflostcount, buffer(offset, 4))
    pifsubtree:add(ifields.piftimeout, buffer(offset, 4))

    offset = offset + 4

    -- iNet-X Payload
    local datasubtree = iNetX_top_subtree:add(buffer(offset, iNetX_payloadsize_in_bytes),
        "iNetX Data (" .. iNetX_payloadsize_in_bytes .. ")")
    
    succ = DissectorTable.try_heuristics("inetx.payload", buffer(offset, iNetX_payloadsize_in_bytes):tvb(), pinfo, datasubtree)
    if not succ then
        datasubtree:add(ifields.payload, buffer(offset, iNetX_payloadsize_in_bytes))
    end
end

local function heuristic_checker(buffer, pinfo, tree)
    -- guard for length
    local length = buffer:len()
    if length < 28 then return false end

    local potential_controlfield = buffer(0,4):uint()

    if potential_controlfield == 0x11000000
    then
        inetx_proto.dissector(buffer, pinfo, tree)
        return true
    else return false end
end
inetx_proto:register_heuristic("udp", heuristic_checker)

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register some ports
--udp_table:add(4444, inetx_proto)
udp_table:add_for_decode_as(inetx_proto)