
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


--------------------------------------------------
-- D-TYPE Messages
-----------------------------------------------
-- declare our protocol
iena_dtype_proto = Proto("iena-d","IENA D-Type")

-- Declare a few fields
f_dtype_paramid = ProtoField.bytes("ienad.paramid","Param ID",base.HEX)
f_dtype_delay = ProtoField.uint32("ienad.delay","Delay",base.DEC)
f_dtype_data = ProtoField.bytes("ienad.data","DataWord",base.HEX)

iena_dtype_proto.fields = {f_dtype_paramid,f_dtype_delay,f_dtype_data}
-- create a function to dissect it
function iena_dtype_proto.dissector(buffer,pinfo,tree)
    
    pinfo.cols.protocol = "iena-d" -- the name in the wirshark view
    local ienad_subtree = tree:add(iena_dtype_proto,buffer(),"IENA-D Message")
    
	local length_buffer = buffer:len()    
	local offset=0
    
	ienad_subtree:add(f_dtype_paramid,buffer(offset,2))
    offset = offset + 2
	ienad_subtree:add(f_dtype_delay,buffer(offset,2))
    offset = offset + 2
    repeat 
        ienad_subtree:add(f_dtype_data,buffer(offset,2))
        offset = offset + 2
    until offset == length_buffer

end
    

--------------------------------------------------
-- M-TYPE Messages
-----------------------------------------------
-- declare our protocol
iena_mtype_proto = Proto("iena-m","IENA M-Type")

-- Declare a few fields
f_mtype_paramid = ProtoField.uint16("ienam.paramid","Param ID",base.HEX)
f_mtype_delay = ProtoField.uint16("ienam.delay","Delay",base.DEC)
f_mtype_length = ProtoField.uint16("ienam.length","Length",base.DEC)
f_mtype_data = ProtoField.bytes("ienam.data","DataSet",base.HEX)
iena_mtype_proto.fields = {f_mtype_paramid,f_mtype_delay,f_mtype_length,f_mtype_data}

-- prefs
-- this can be overwritten in the Preference page
iena_mtype_proto.prefs["messagedissector"] = Pref.string("Message Dissector","lxrs","What dissector to use for the message data")

-- create a function to dissect it
function iena_mtype_proto.dissector(buffer,pinfo,tree)
    
    pinfo.cols.protocol = "iena-m" -- the name in the wirshark view
    local ienam_subtree = tree:add(iena_mtype_proto,buffer(),"IENA-M Message")
	local length_buffer = buffer:len()
	local offset=0
    
	ienam_subtree:add(f_mtype_paramid,buffer(offset,2))
    offset = offset + 2
	ienam_subtree:add(f_mtype_delay,buffer(offset,2))
    offset = offset + 2
	ienam_subtree:add(f_mtype_length,buffer(offset,2))
    local datalen = buffer(offset,2):uint()
    offset = offset + 2
    if iena_mtype_proto.prefs["messagedissector"] then
        messagedissector = Dissector.get(iena_mtype_proto.prefs["messagedissector"])
        messagedissector:call(buffer(offset,length_buffer-6):tvb(),pinfo,ienam_subtree)
    end
end


--------------------------------------------------
-- P-TYPE Messages
-----------------------------------------------
-- declare our protocol
iena_ptype_proto = Proto("iena-p","IENA P-Type")

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
    repeat
        local pattern_subtree = ienap_subtree:add(buffer(offset,pref_messages_per_pattern),"Pattern " .. pattern_count)
        local word_count = 0
        repeat
            pattern_subtree:add(buffer(offset,2),"Word " .. word_count .. "=".. (buffer(offset,2)))
            offset = offset + 2
            word_count = word_count + 1
        until word_count == pref_messages_per_pattern
        pattern_count = pattern_count + 1
    until offset == length_buffer


end
    