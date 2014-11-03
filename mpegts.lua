
-------------------------------------------------------
-- This is a basic Wireshark dissector for the MPEG Transport Stream Payload
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


-- This dissects an MPEG TS Block
mpegts_proto = Proto("mpegts","MPEG2 Transport Stream")
-- Declare a few fields that we are in
f_syncbyte = ProtoField.float("mpegts.sync","SyncByte",base.HEX)
f_pid = ProtoField.float("mpegts.pid","PID",base.HEX)
f_continuity = ProtoField.float("mpegts.continuity","Continuity",base.DEC)

mpegts_proto.fields = {f_syncbyte,f_pid,f_continuity}

-- create a function to dissect it
function mpegts_proto.dissector(buffer,pinfo,tree)

	pinfo.cols.protocol = "mpegts"
	--local datasubtree = tree:add(bcutemperature_proto,buffer(),"BCU Temperature")	
	offset = 0
	tree:add(f_syncbyte,buffer(offset,1),buffer(offset,1):int())
	offset = offset + 1
	local pidbyte = buffer(offset,2):int()
	pidbyte = pidbyte % 8192
	tree:add(f_pid,buffer(offset,2),pidbyte)
	offset = offset + 2
	local contbyte = buffer(offset,1):int()
	contbyte = contbyte % 16
	tree:add(f_continuity,buffer(offset,1),contbyte)
	offset = offset + 1
	tree:add(buffer(offset,(188-offset)),"Payload Data")
end