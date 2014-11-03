
-------------------------------------------------------
-- This is a Wireshark dissector for the Airbus IENA packet format
-------------------------------------------------------

-- Copyright 2014 Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuid
-- https://github.com/diarmuidcwc/LuaDissectors


-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


-- To use this dissector you need to include this file in your init.lua as follows:

-- CUSTOM_DISSECTORS = DATA_DIR.."LuaDissectors" -- Replace with the directory containing all the scripts
-- dofile(CUSTOM_DISSECTORS.."\\xxx.lua")

dofile(CUSTOM_DISSECTORS.."\\common.lua")
dofile(CUSTOM_DISSECTORS.."\\enc106.lua")

-- some ports of interest
ENC106_PLL_PORT = 2043
-- declare our protocol
iena_generic_proto = Proto("iena","IENA Protocol")

-- Declare a few fields
f_ienakey = ProtoField.bytes("iena.key","Key",base.HEX)
f_size = ProtoField.uint32("iena.size","Size",base.DEC)
f_time = ProtoField.bytes("iena.time","Time",base.DEC)
f_keystatus = ProtoField.bytes("iena.keystatus","Key Status",base.HEX)
f_n2status = ProtoField.bytes("iena.n2status","N2 Status",base.HEX)
f_sequencenum = ProtoField.uint32("iena.sequencenum","Sequence Number",base.DEC)
f_trailer = ProtoField.bytes("iena.trailer","IENA Trailer",base.HEX)

iena_generic_proto.fields = {f_ienakey,f_size,f_time,f_keystatus,f_n2status,f_sequencenum,f_trailer}

-- create a function to dissect it
function iena_generic_proto.dissector(buffer,pinfo,tree)

    pinfo.cols.protocol = "iena" -- the name in the wirshark view
    local iena_top_subtree = tree:add(iena_generic_proto,buffer(),"IENA Protocol Data")
	
	
	-- create a subtree for the IENA Header
	subtree = iena_top_subtree:add(buffer(0,14),"IENA Header")
	local offset=0
	subtree:add(f_ienakey,buffer(offset,2))
	offset = offset + 2
	subtree:add(f_size,buffer(offset,2))
	offset = offset + 2
	local iena_size_in_words = buffer(2,2):uint()
	subtree:add(f_time,buffer(offset,6))
	-- iena time is time since first sec of this year
	-- lua can't handle 6byte integers so first truncate the last 2 bytes and then compensate for that later
	-- probably something lost in the rounding but good enough
	local time_in_usec = buffer(offset,4):uint() -- this is actually usec divided by 2^16
	local ostime_this_year = os.time{year=2010, month=1, day=1, hour=0, min=0, sec=0} -- get the 1st jan this year
	subtree:add(buffer(offset,6),"Date: " .. os.date("!%H:%M:%S %d %b %Y",(ostime_this_year + time_in_usec/15.2587890625)))
	offset = offset + 6
	subtree:add(f_keystatus,buffer(offset,1))
	offset = offset + 1
	subtree:add(f_n2status,buffer(offset,1))
	offset = offset + 1
	subtree:add(f_sequencenum,buffer(offset,2))
	offset = offset + 2
	
	
	-- Now in the payload
	if(pinfo.dst_port == ENC106_PLL_PORT) then
		enc106_pll_proto_dissector = Dissector.get("enc106_pll")
		enc106_pll_proto_dissector:call(buffer(offset,10):tvb(),pinfo,subtree)
	else
		datasubtree = iena_top_subtree:add(buffer(14,(iena_size_in_words*2-16)),"Data")
		offset = offset + iena_size_in_words*2-16
		
	end	
	
	-- the trailer
	subtree:add(f_trailer,buffer(offset,2))	
	

  end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register some ports
udp_table:add(ENC106_PLL_PORT,iena_generic_proto)
