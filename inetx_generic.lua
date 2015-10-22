
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
dofile(CUSTOM_DISSECTORS.."\\LXRS.lua")

-- Hook up dissectors to certain ports. You need to add these 
-- ports at the bottom if you want them automatically dissected
PARSER_ALIGNED_PORT = 9010
VIDEO_PORT = 8010
TRAFFIC_GENERATOR_PORT = 3344
BCU_TEMPERATURE_PORT = 23454
MAT101_PORT = 1023
VID106_REPORT_PORT = 5523
ADC114_PORT = 5567
TCG105_PORT = 9898
TCG102_PORT = 9899
LXRS_PORT = 5555
LXRS_ID = 0xdc1
WSI104_ID  = 0xcd2
WSI104_ID2 = 0xdc4
WSI104_REPORT = 0xdc6
WSI104_NODE_1 = 0xdc3
WSI104_NODE_2 = 0xdc4


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
	
	-- payload contains multiple video report words
	if(pinfo.dst_port == VID106_REPORT_PORT) then
		vid106report_dissector = Dissector.get("vid106report")
		vid106report_dissector:call(buffer(offset,pinfo.len-70):tvb(),pinfo,subtree)
	end		
    

-- def calcValue(data=0, rmax = 540, rmin = -200 ):
    -- d = data
    -- mx = rmax
    -- mn = rmin
    -- r  = (mx - mn) + 0.0
    -- v = ((d+0.0)/65536.0) *  r + (mn +0.5)	
	
	if(pinfo.dst_port == ADC114_PORT) then
	  pinfo.cols.protocol = "ADC114"	
      -- DATA IN ADC PACKETS ---
      local channel = 0
      datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"ADC114 Payload")
      repeat 
		raw_temp = buffer(offset,2):uint()
		temp = math.floor((raw_temp/65536) * 740 - 200.5)

		datasubtree:add(buffer(offset,2),"Temperature Ch" .. channel .. "=" .. temp)
        offset = offset + 2
		channel = channel + 1
      until (offset == iNetX_payloadsize_in_bytes+28)		
	end	
	
	if(pinfo.dst_port == TCG105_PORT) then
		pinfo.cols.protocol = "TCG105"	
		-- DATA IN tcg105 PACKETS ---
		datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"TCG105 and BCU140D Payload")
		-- some data words
		datasubtree:add(buffer(offset,2),"BCU140D_REPORT: " .. buffer(offset,2))
        offset = offset + 2
		datasubtree:add(buffer(offset,2),"TCG105_STATUS: " .. buffer(offset,2))
        offset = offset + 2
		datasubtree:add(buffer(offset,2),"BCU140_DOY: " .. buffer(offset,2):uint())
        offset = offset + 2
		-- bcu time
		local sbi_time = tostring(buffer(offset,6))
		local usec = string.sub(sbi_time,-6)
		local wall_time = sbi_to_walltime(sbi_time)
		datasubtree:add(buffer(offset,6),"BCU140_Time (ptp equivalent): " .. os.date("!%H:%M:%S",wall_time+35))
		offset = offset + 6
		-- tcg time
		local sbi_time = tostring(buffer(offset,6))
		local usec = string.sub(sbi_time,-6)
		local wall_time = sbi_to_walltime(sbi_time)
		datasubtree:add(buffer(offset,6),"TCG105_Time (ptp equivalent): " .. os.date("!%H:%M:%S",wall_time+35))
		offset = offset + 6
		datasubtree:add(buffer(offset,2),"TCG_DOY: " .. buffer(offset,2):uint())
        offset = offset + 2
		datasubtree:add(buffer(offset,2),"RTC_DOY: " .. buffer(offset,2):uint())
        offset = offset + 2
		local rtc_ptp =  buffer(offset,2):uint()
		datasubtree:add(buffer(offset,2),"RTC_PTP: " .. rtc_ptp)
		datasubtree:add(buffer(offset,2),"RTC_Date: " .. os.date("%x",rtc_ptp*86400))
        offset = offset + 2
		datasubtree:add(buffer(offset,2),"TCG_DOY: " .. buffer(offset,2):uint())
        offset = offset + 2
		local tcg_ptp =  buffer(offset,2):uint()
		datasubtree:add(buffer(offset,2),"TCG_PTP: " .. tcg_ptp)
		datasubtree:add(buffer(offset,2),"TCG_Date: " .. os.date("%x",tcg_ptp*86400))
		offset = offset + 2
		local bcu_ptp =  buffer(offset,2):uint()
		datasubtree:add(buffer(offset,2),"BCU_PTPDays: " .. bcu_ptp)
		datasubtree:add(buffer(offset,2),"BCU_Date: " .. os.date("%x",bcu_ptp*86400))
        offset = offset + 2
		datasubtree:add(buffer(offset,2),"RTC_HHMM: " .. buffer(offset,2):uint())
        offset = offset + 2
		datasubtree:add(buffer(offset,2),"TCG_HHMM: " .. buffer(offset,2):uint())
		offset = offset + 2
		local tcg_vendor_ptp =  buffer(offset,2):uint()
		datasubtree:add(buffer(offset,2),"TCG_PTPDaysVendor: " .. tcg_vendor_ptp)
		datasubtree:add(buffer(offset,2),"TCG_PTPDaysVendor: " .. os.date("%x",tcg_vendor_ptp*86400))
        
		
	end		
	
	if(pinfo.dst_port == TCG102_PORT) then
		pinfo.cols.protocol = "TCG105"	
		-- DATA IN tcg105 PACKETS ---
		datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"TCG105 and BCU140D Payload")
		-- some data words
		local bcu_ptp =  buffer(offset,2):uint()
		datasubtree:add(buffer(offset,2),"BCU_PTPDays: " .. bcu_ptp)
		datasubtree:add(buffer(offset,2),"BCU_Date: " .. os.date("%x",bcu_ptp*86400))
        offset = offset + 2
		-- bcu time
		local sbi_time = tostring(buffer(offset,6))
		local usec = string.sub(sbi_time,-6)
		local wall_time = sbi_to_walltime(sbi_time)
		datasubtree:add(buffer(offset,6),"BCU140_Time (ptp equivalent): " .. os.date("!%H:%M:%S",wall_time+35))
		offset = offset + 6
		-- tcg time
		local sbi_time = tostring(buffer(offset,6))
		local usec = string.sub(sbi_time,-6)
		local wall_time = sbi_to_walltime(sbi_time)
		datasubtree:add(buffer(offset,6),"TCG105_Time (ptp equivalent): " .. os.date("!%H:%M:%S",wall_time+35))
		offset = offset + 6
		datasubtree:add(buffer(offset,2),"GPS_Status: " .. buffer(offset,2):uint())
        
		
	end			
	-- Example of a dissector which depends on the length of a packet
	if(pinfo.len == 1199 or pinfo.len == 1198) then
	
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

    -- WSI 104 debug
	-- payload contains a n LXRS packet
	if(pinfo.dst_port == LXRS_PORT) then
        if stream_id_v == LXRS_ID then
            pinfo.cols.protocol = "LXRS"	
            lxrs_dissector = Dissector.get("lxrs")
            lxrs_dissector:call(buffer(offset,iNetX_payloadsize_in_bytes):tvb(),pinfo,subtree)
        elseif (stream_id_v == WSI104_REPORT) then
            pinfo.cols.protocol = "WSI104_REPORT"
            -- Report IN WSI PACKETS ---
            local channel = 0
            datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"WSI104 Report")
            repeat 
                raw_value = buffer(offset,2):uint()
                undersampling = bit32.extract(raw_value,0,1)
                oversampling = bit32.extract(raw_value,1,1)
                if oversampling == 1 then
                    datasubtree:add(buffer(offset,2),"Channel " .. channel .. " = " .. raw_value .. " is oversampling")
                end 
                if undersampling == 1 then
                    datasubtree:add(buffer(offset,2),"Channel " .. channel .. " = " .. raw_value .. " is undersampling")
                end
                if oversampling == 0 and undersampling == 0 then
                    datasubtree:add(buffer(offset,2),"Channel " .. channel .. " = " .. raw_value)
                end
                channel = channel + 1
                offset = offset + 2
            until (offset == iNetX_payloadsize_in_bytes+28)	
        elseif (stream_id_v == WSI104_ID or stream_id_v == WSI104_ID2 ) then
            pinfo.cols.protocol = "WSI104_DATA"	
            -- DATA IN WSI PACKETS ---
            local channel = 0
            datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"WSI104 Payload")
            description = "Channel "
            repeat 
                raw_value = buffer(offset,2):uint()
                datasubtree:add(buffer(offset,2),description .. channel .. "=" .. buffer(offset,2))
                channel = channel + 1
                offset = offset + 2
            until (offset == iNetX_payloadsize_in_bytes+28)	
        elseif (stream_id_v == WSI104_NODE_1 or stream_id_v == WSI104_NODE_2) then
            pinfo.cols.protocol = "WSI104_node"
            datasubtree = iNetX_top_subtree:add(buffer(offset,(iNetX_payloadsize_in_bytes)),"Node Data")
            local active_channels = 4
            local channel = 1 
            local sweep_count = 1
            repeat
                local sweep_tree =  datasubtree:add(buffer(offset,2*active_channels),"Pattern " .. sweep_count)
                local ch = 1
                repeat
                    sweep_tree:add(buffer(offset,2),"Channel: " .. ch .. " = " .. buffer(offset,2):uint())
                    offset = offset + 2
                    ch = ch + 1
                until (ch == active_channels+1)
                sweep_count = sweep_count + 1
            until (offset == iNetX_payloadsize_in_bytes+28)
        end
	end		
    

    
end

-- This is where you can hook up ports automatically
-- So for instance if you want the inetx dissector automatically
-- run on the VIDEO_PORT

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port VIDEO_PORT
udp_table:add(VIDEO_PORT,inetx_generic_proto)
udp_table:add(ADC114_PORT,inetx_generic_proto)
udp_table:add(VID106_REPORT_PORT,inetx_generic_proto)
udp_table:add(TCG105_PORT,inetx_generic_proto)
udp_table:add(LXRS_PORT,inetx_generic_proto)

