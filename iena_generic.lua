
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

--dofile(CUSTOM_DISSECTORS.."\\common.lua")
--dofile(CUSTOM_DISSECTORS.."\\enc106.lua")
--dofile(CUSTOM_DISSECTORS.."\\iena_subtypes.lua")
--dofile(CUSTOM_DISSECTORS.."\\parser_aligned.lua")

-- some ports of interest
ENC106_PLL_PORT = 2043
VID106_PORT     = 7002
WSI_PORT        = 51000
ABM_PORT        = 21000
IENAN_PORT      = 5547
IENAD_PORT      = 5548
IENAM_PORT      = 5550
IENAQ_PORT      = 5549

LXRS_ID = 0xF6Ae


-- declare our protocol
iena_generic_proto = Proto("iena","IENA Protocol")

-- Declare a few fields
f_ienakey = ProtoField.uint16("iena.key","Key",base.HEX)
f_size = ProtoField.uint32("iena.size","Size",base.DEC)
f_time = ProtoField.uint64("iena.time","Time",base.DEC)
f_sec = ProtoField.uint32("iena.seconds","Seconds",base.DEC)
f_usec = ProtoField.uint32("iena.useconds","MicroSeconds",base.DEC)
f_keystatus = ProtoField.uint16("iena.keystatus","Key Status",base.HEX)
f_n2status = ProtoField.uint16("iena.n2status","N2 Status",base.HEX)
f_sequencenum = ProtoField.uint32("iena.sequencenum","Sequence Number",base.DEC)
f_trailer = ProtoField.uint32("iena.trailer","IENA Trailer",base.HEX)

iena_generic_proto.fields = {f_ienakey,f_size,f_time,f_sec,f_usec,f_keystatus,f_n2status,f_sequencenum,f_trailer}

-- create a function to dissect it
function iena_generic_proto.dissector(buffer,pinfo,tree)

    pinfo.cols.protocol = "iena" -- the name in the wirshark view
    local iena_top_subtree = tree:add(iena_generic_proto,buffer(),"IENA Protocol Data")
	
	
	-- create a subtree for the IENA Header
	subtree = iena_top_subtree:add(buffer(0,14),"IENA Header")
	local offset=0
	subtree:add(f_ienakey,buffer(offset,2))
    local key_id_v = buffer(offset,2):uint()
	offset = offset + 2
	subtree:add(f_size,buffer(offset,2))
    local size_v = buffer(offset,2):uint()
	offset = offset + 2
	local iena_size_in_words = size_v
	subtree:add(f_time,buffer(offset,6))
	-- iena time is time since first sec of this year
	-- lua can't handle 6byte integers so first truncate the last 2 bytes and then compensate for that later
	-- probably something lost in the rounding but good enough
	local time_in_usec = buffer(offset,4):uint() -- this is actually usec divided by 2^16
	local ostime_this_year = os.time{year=2010, month=1, day=1, hour=0, min=0, sec=0} -- get the 1st jan this year
	subtree:add(buffer(offset,6),"Date: " .. os.date("!%H:%M:%S %d %b %Y",(ostime_this_year + time_in_usec/15.2587890625)))
        trunc_sec = buffer(offset+2,4):uint()
        hi_sec = buffer(offset,2):uint() * 4294967296
        totalusec = hi_sec + trunc_sec
    
    subtree:add(f_sec, buffer(offset,6), math.floor(totalusec/1e6))
    subtree:add(f_usec, buffer(offset,6), totalusec % 1e6)
    
	--subtree:add(buffer(offset,6),"Seconds: " .. math.floor(totalusec/1e6))
    --subtree:add(buffer(offset,6),"MicroSeconds: " .. totalusec % 1e6)
    
    
	offset = offset + 6
	subtree:add(f_keystatus,buffer(offset,1))
    local v_data_words_n_d = buffer(offset,1):uint() % 8
	offset = offset + 1
	subtree:add(f_n2status,buffer(offset,1))
	offset = offset + 1
	subtree:add(f_sequencenum,buffer(offset,2))
	offset = offset + 2
	
	-- some custom dissectors now called
    if (pinfo.dst_port == WSI_PORT) then
        if key_id_v == LXRS_ID then
            ienamdissector = Dissector.get("iena-m")
            ienamdissector:call(buffer(offset,iena_size_in_words*2-16):tvb(),pinfo,subtree)
            offset = offset + iena_size_in_words*2-22
        else
            ienapdissector = Dissector.get("iena-p")
            ienapdissector:call(buffer(offset,iena_size_in_words*2-16):tvb(),pinfo,subtree,4)
            offset = offset + iena_size_in_words*2-22
        end
    elseif (pinfo.dst_port == ABM_PORT) then
        parseraligneddissector = Dissector.get("parseraligned")
        parseraligneddissector:call(buffer(offset,iena_size_in_words*2-16):tvb(),pinfo,subtree,4)
        offset = offset + iena_size_in_words*2-22
        
    -- IENA- N Messages
    elseif (tonumber(pinfo.dst_port) == IENAN_PORT) then
        n_len_bytes = (v_data_words_n_d + 1) * 2 -- ParamID
        n_instances = (iena_size_in_words*2 - 14 - 2) / n_len_bytes
        -- keystatus field contain the number of D words so calculate the lenght of IENA-N message from that
        for nmessage=1,n_instances do
            ienan_subtree = iena_top_subtree:add(buffer(offset,n_len_bytes),"IENA-N Message #" .. nmessage)
            ienandiss = Dissector.get("iena-n")
            ienandiss:call(buffer(offset,n_len_bytes):tvb(),pinfo,ienan_subtree)
            offset = offset + n_len_bytes
        end
    elseif (pinfo.dst_port == IENAD_PORT) then
        d_len_bytes = (v_data_words_n_d + 2) * 2 -- ParamID + Delat
        d_instances = (iena_size_in_words * 2 - 14 - 2) / d_len_bytes
        -- keystatus field contain the number of D words so calculate the lenght of IENA-D message from that
        for dmessage=1,d_instances do
            ienad_subtree = iena_top_subtree:add(buffer(offset,d_len_bytes),"IENA-D Message #" .. dmessage .. " " .. d_instances)
            ienaddiss = Dissector.get("iena-d")
            ienaddiss:call(buffer(offset,d_len_bytes):tvb(),pinfo,ienad_subtree)
            offset = offset + d_len_bytes
        end
    elseif (pinfo.dst_port == IENAM_PORT) then
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
    elseif (pinfo.dst_port == IENAQ_PORT) then
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
	subtree:add(f_trailer,buffer((iena_size_in_words*2)-2,2))	
	

  end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register some ports
udp_table:add(ENC106_PLL_PORT,iena_generic_proto)
udp_table:add(WSI_PORT,iena_generic_proto)
udp_table:add(ABM_PORT,iena_generic_proto)
udp_table:add(IENAN_PORT,iena_generic_proto)
udp_table:add(IENAD_PORT,iena_generic_proto)
udp_table:add(IENAM_PORT,iena_generic_proto)
udp_table:add(IENAQ_PORT,iena_generic_proto)
