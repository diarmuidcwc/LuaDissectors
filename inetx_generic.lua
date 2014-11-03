
-------------------------------------------------------
-- This is a Wireshark dissector for the iNet-X packet format
-- http://www.cwc-ae.com/custom/pdfs/White%20Paper_iNET-X_packets.pdf
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
-- dofile(CUSTOM_DISSECTORS.."\\inetx_generic.lua")



-- Common functions. These are always needed
dofile(CUSTOM_DISSECTORS.."\\common.lua")
dofile(CUSTOM_DISSECTORS.."\\parse_arinc.lua")

-- These are some custom iNetX payloads that I want to dissect.
-- These can be commented out if not needed
dofile(CUSTOM_DISSECTORS.."\\bcu_status.lua")
dofile(CUSTOM_DISSECTORS.."\\psu.lua")
dofile(CUSTOM_DISSECTORS.."\\mat_101.lua")
dofile(CUSTOM_DISSECTORS.."\\bcu_temperature.lua")
dofile(CUSTOM_DISSECTORS.."\\trfgen.lua")
dofile(CUSTOM_DISSECTORS.."\\mpegts.lua")

-- Hook up dissectors to certain ports. You need to add these 
-- ports at the bottom if you want them automatically dissected
PARSER_ALIGNED_PORT = 9010
VIDEO_PORT = 8011
TRAFFIC_GENERATOR_PORT = 3344
BCU_TEMPERATURE_PORT = 23454
MAT101_PORT = 1023

-- trivial protocol example
-- declare our protocol
inetx_generic_proto = Proto("inetx","Generic iNetX Protocol")

-- Declare a few fields
f_inetcontrol = ProtoField.bytes("inetx.control","Control",base.HEX)
f_streamid = ProtoField.bytes("inetx.streamid","StreamID",base.HEX)
f_inetsequencenum = ProtoField.uint32("inetx.sequencenum","Sequence Number",base.DEC)
f_packetlen = ProtoField.uint32("inetx.packetlen","Packet Length",base.DEC)
f_ptpseconds = ProtoField.uint32("inetx.ptpseconds","PTP Seconds",base.DEC)
f_ptpnanoseconds = ProtoField.uint32("inetx.ptpnanoseconds","PTP Nanoseconds",base.DEC)
f_pif = ProtoField.bytes("inetx.pif","PIF",base.HEX)

inetx_generic_proto.fields = {f_inetcontrol,f_streamid,f_inetsequencenum,f_packetlen,f_ptpseconds,f_ptpnanoseconds,f_pif}



-- create a function to dissect it
function inetx_generic_proto.dissector(buffer,pinfo,tree)


  udp_dst_f = pinfo.dst_port
  pinfo.cols.protocol = "inetx"
  local iNetX_top_subtree = tree:add(inetx_generic_proto,buffer(),"iNet-X Protocol Data")
  
  -- The iNet-X Header Definition
  
  subtree = iNetX_top_subtree:add(buffer(0,28),"inetx Header")
  local offset=0
  
  subtree:add(f_inetcontrol,buffer(offset,4))
  offset = offset + 4
  
  subtree:add(f_streamid,buffer(offset,4))
  local stream_id_v = buffer(offset,4):uint()
  offset = offset + 4
  
  subtree:add(f_inetsequencenum,buffer(offset,4))
  offset = offset + 4
  
  subtree:add(f_packetlen,buffer(offset,4))
  local iNetX_payloadsize_in_bytes = buffer(offset,4):uint() - 28
  offset = offset + 4
  
  ptptimesubtree = subtree:add(buffer(offset,8),"PTPTimeStamp")
  if ( buffer(offset,4):uint() > 1576800000 ) then
    ptptimesubtree:add(buffer(offset,4),"Date: ERROR. Some time after 2020")
  else
    ptptimesubtree:add(buffer(offset,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset,4):uint()))
  end
  ptptimesubtree:add(f_ptpseconds,buffer(offset,4))
  offset = offset + 4
  
  ptptimesubtree:add(f_ptpnanoseconds,buffer(offset,4))
  offset = offset + 4
  
  subtree:add(f_pif,buffer(offset,4))
  offset = offset + 4
   
  -- iNet-X Payload
  subtree = iNetX_top_subtree:add(buffer(offset,iNetX_payloadsize_in_bytes),"iNetX Data (" .. iNetX_payloadsize_in_bytes .. ")" )
    
  if ( pinfo.dst_port == PARSER_ALIGNED_PORT ) then
      -- DATA IN AUTOMATIC PACKETS ---
      local slot = 1
      datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"iNetX Payload (ETH) (Packetizer)")
      repeat 
        slotsubtree = datasubtree:add(buffer(offset,12),"Parser Block: " .. slot)
        local error_code = (buffer(offset,1):uint())/16
        slotsubtree:add(buffer(offset,2),"Error Code: " .. error_code)
        local quad_bytes = (buffer(offset,2):uint()) % 256
        slotsubtree:add(buffer(offset,2),"Quad Bytes: " .. quad_bytes)
        offset = offset + 2
        slotsubtree:add(buffer(offset,1),"Message Count: " .. buffer(offset,1):uint())
        offset = offset + 1
        slotsubtree:add(buffer(offset,1),"Bus ID: " .. buffer(offset,1):uint())
        offset = offset + 1
        slotsubtree:add(buffer(offset,4),"Elapsed Time: " .. buffer(offset,4):uint())
        offset = offset + 4
        local quad_count = 0
        repeat
          local pdetail = parse_arinc_detail(buffer(offset,1):uint(),buffer(offset+1,1):uint(),buffer(offset+2,1):uint(),buffer(offset+3,1):uint())
          slotsubtree:add(buffer(offset,4),pdetail)
          offset = offset + 4
          quad_count = quad_count + 1
        until (quad_count == quad_bytes-2)
        slot = slot + 1
      until (offset == iNetX_payloadsize_in_bytes+28)
  end
  
  
  -- sample dissector for VID 106 payload
  if ( pinfo.dst_port == VIDEO_PORT ) then
     pinfo.cols.protocol = "VID106"
     fastmode = false
      -- DATA IN VIDEO PACKETS ---
      local slot = 1
      datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"iNetX Payload (VID)")
      repeat 
        syncword = tostring(buffer(offset,3))
        if ( syncword == "470100" or  syncword == "470101" or syncword == "474100" or syncword == "474101" or syncword == "471FFF" or syncword == "474000" or syncword == "475000"  ) then
            insync = "In Sync"
        else
            insync = "Out of Sync"
        end
		mpegtsdissector = Dissector.get("mpegts")
		block_tree = datasubtree:add(buffer(offset,188),"MPEG Block "..slot)
		mpegtsdissector:call(buffer(offset,188):tvb(),pinfo,block_tree)
        offset = offset + 188
        slot = slot + 1
      until (offset == iNetX_payloadsize_in_bytes+28)
  end
  
	-- payload contains a customer dissector. Call it here
	if(pinfo.dst_port == TRAFFIC_GENERATOR_PORT) then
		bcutemp_dissector = Dissector.get("trfgen")
		bcutemp_dissector:call(buffer(offset,18):tvb(),pinfo,subtree)
	end	

	-- payload contains a customer dissector. Call it here
	if(pinfo.dst_port == BCU_TEMPERATURE_PORT) then
		bcutemp_dissector = Dissector.get("bcutemperature")
		bcutemp_dissector:call(buffer(offset,4):tvb(),pinfo,subtree)
	end		
	
	-- Example of a dissector which depends on the length of a packet
	if(pinfo.len == 92 or pinfo.len == 98) then
	
		-- Hook the BCU dissector onto this depending on the size

		if (stream_id_v == 0x13) then
			dau = 0
		elseif (stream_id_v == 0x22) then
			dau = 1
		elseif (stream_id_v == 0x32) then
			dau = 2
		elseif (stream_id_v == 0x42) then
			dau = 3
		elseif (stream_id_v == 0x2) then
			dau = "m"
		else 
			dau = "unknown"
		end
		
		-- 
		local buf_size = 22
		if(pinfo.len == 98) then
			buf_size = 28
		end
		subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"Dau "..dau.." Status")
		bcu_dissector = Dissector.get("bcureport")
		bcu_dissector:call(buffer(offset,buf_size):tvb(),pinfo,subtree)
	end
	
	-- payload contains a customer dissector. Call it here
 	if(pinfo.dst_port == MAT101_PORT) then
		mat101_dissector = Dissector.get("mat101")
		mat101_dissector:call(buffer(offset,44):tvb(),pinfo,subtree)
	end   
    
end

-- This is where you can hook up ports automatically
-- So for instance if you want the inetx dissector automatically
-- run on the VIDEO_PORT

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port VIDEO_PORT
udp_table:add(VIDEO_PORT,inetx_generic_proto)
