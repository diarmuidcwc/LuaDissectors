

-- Copyright 2014 Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuid
-- https://github.com/diarmuidcwc/LuaDissectors


-- To use this dissector you need to include this file in your init.lua as follows:

-- CUSTOM_DISSECTORS = DATA_DIR.."LuaDissectors" -- Replace with the directory containing all the scripts
-- dofile(CUSTOM_DISSECTORS.."\\inetx_generic.lua")

-- Common functions. These are always needed
--dofile(CUSTOM_DISSECTORS.."\\common.lua")
--dofile(CUSTOM_DISSECTORS.."\\parse_arinc.lua")

DEM_PORT = 8012
--CH10_PORT = 8010




--function ch10_timeprotocol1.dissector(buffer, pinfo, tree)
--	offset = 0
--	tree:add_le(f_ch10timecsd, buffer(offset,4))
--	offset = offset + 4
--	local ms = tonumber(tostring(buffer(offset,1))) * 10
--	local s = tonumber(tostring(buffer(offset+1,1)))
--    local m = tonumber(tostring(buffer(offset+2,1)))
--    local h = tonumber(tostring(buffer(offset+3,1)))
--	local doy = tonumber(tostring(buffer(offset+5,1)) ..  tostring(buffer(offset+4,1)))
--
--	tree:add(buffer(offset,6), string.format("DOY=%d Time=%d:%d:%d Milliseconds=%d", doy, h,m,s,ms))
--
--end


dem_generic_proto = Proto("dem","DEM Protocol")

--
-- Define our DEM fields apart from the FCS style CRC at the end.
--

f_dem_total_size = ProtoField.uint16("dem.total_size","Total Size",base.HEX)
f_dem_misc_a     = ProtoField.uint8("dem.misc_a","Ver|CRC|cmap",base.HEX)
f_dem_flags      = ProtoField.uint8("dem.flags","Flags",base.HEX)
f_dem_system_id  = ProtoField.uint16("dem.system_id","System ID|HeaderType ID",base.HEX)
f_dem_content_id = ProtoField.uint16("dem.content_id","Content ID",base.HEX)
f_dem_secs       = ProtoField.uint32("dem.seconds","Seconds",base.DEC)
f_dem_fsecs      = ProtoField.uint16("dem.fseconds","FSeconds",base.DEC)

-- and list our fields:



dem_generic_proto.fields = {f_dem_total_size,f_dem_misc_a,f_dem_flags,f_dem_system_id,f_dem_content_id,f_dem_secs,f_dem_fsecs}


function  dem_generic_proto.dissector(buffer,pinfo,tree)


    pinfo.cols.protocol = "DEM" -- the name in the wireshark view
    local dem_top_subtree = tree:add(dem_generic_proto,buffer(),"DEM Protocol")

	-- create a subtree for the IENA Header
	subtree = dem_top_subtree:add(buffer(0,0),"DEM Header")


    local offset=0
    subtree:add(buffer(offset, 24), "DEM Packet")

	subtree:add(f_dem_total_size,buffer(offset,2))
	offset = offset + 2

	subtree:add_le(f_dem_misc_a,buffer(offset,1))
	offset = offset + 1

	subtree:add_le(f_dem_flags,buffer(offset,1))
    offset = offset + 1

    subtree:add_le(f_dem_system_id,buffer(offset,2))
    offset = offset + 2

    subtree:add_le(f_dem_content_id,buffer(offset,2))
    offset = offset + 2

    -- DEM Time is counted from 6th Jan 1980 instead of 1st Jan 1970 (GPS Epoch).

    --subtree:add_le(f_dem_secs,buffer(offset,4), "DEM Time")
    subtree:add(buffer(offset,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset,4):uint() + 315964800))

    offset = offset + 4
    subtree:add_le(f_dem_fsecs,buffer(offset,2))
    offset = offset + 2


end


-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register some ports
udp_table:add(DEM_PORT,dem_generic_proto)
