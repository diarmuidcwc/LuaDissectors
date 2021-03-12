
-------------------------------------------------------
-- This is a Wireshark dissector for the KAD/MEM/004 programming protocol
-- http://www.cwc-ae.com/product/kadmem004
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
-- trivial protocol example
-- declare our protocol
mem_proto = Proto("mem004","KAD/MEM/004")
-- The command side
f_cmd_type = ProtoField.float("mem004.cmd","Cmd.Type",base.DEC)
f_cmd_sequence = ProtoField.uint32("mem004.cmd","Cmd.Sequence",base.DEC)
f_cmd_sectoraddr = ProtoField.float("mem004.cmd","Cmd.SectorAddress",base.DEC)
f_cmd_numsector = ProtoField.float("mem004.cmd","Cmd.NumOfSectors",base.DEC)


mem_proto.fields = {f_cmd_type,f_cmd_sequence,f_cmd_sectoraddr,f_cmd_numsector}

-- create a function to dissect it
function mem_proto.dissector(buffer,pinfo,tree)
  udp_dst_f = pinfo.dst_port
  udp_src_f = pinfo.src_port
  
  local search_for_zeros = true;
  
  local mem_top_subtree = tree:add(mem_proto,buffer(),"Mem004 Protocol Data")
  local offset=0

  
  -- this is the commands from kFlashcard
  if ( pinfo.dst_port == 4096 ) then
    pinfo.cols.protocol = "mem004.cmd"
    -- Read CMD
    local slot = 1
    datasubtree = mem_top_subtree:add(buffer(offset,1),"Command")
    local commandcode = buffer(offset,1):uint()
    datasubtree:add(buffer(offset,1),"Command Code: " .. commandcode)
    if ( commandcode == 16 ) then
        datasubtree:add(buffer(offset,1),"ReadStatus = Stop Logging")
        offset = offset + 1
        datasubtree:add(buffer(offset,1),"Command Seq Num: " .. buffer(offset,1):uint())
    elseif  ( commandcode == 32 ) then
        datasubtree:add(buffer(offset,1),"ReadStatus = Restart Logging")
        offset = offset + 1
        datasubtree:add(buffer(offset,1),"Command Seq Num: " .. buffer(offset,1):uint())
    elseif  ( commandcode == 0 ) then
        datasubtree:add(buffer(offset,1),"ReadStatus = ReadStatus")
        offset = offset + 1
        datasubtree:add(buffer(offset,1),"Command Seq Num: " .. buffer(offset,1):uint())
    elseif ( commandcode == 1 ) then
        datasubtree:add(buffer(offset,1),"Read")
        offset = offset + 1
        datasubtree:add(buffer(offset,1),"Command Seq Num: " .. buffer(offset,1):uint())
        offset = offset + 1
        datasubtree:add(buffer(offset,4),"Sector Addr= " .. buffer(offset,4):uint())
    elseif  ( commandcode == 2 ) then
        datasubtree:add(buffer(offset,1),"Write")
        offset = offset + 1
        datasubtree:add(buffer(offset,1),"Command Seq Num: " .. buffer(offset,1):uint())
        offset = offset + 1
     elseif  ( commandcode == 4 ) then
        datasubtree:add(buffer(offset,1),"Init0")
        offset = offset + 1
        datasubtree:add(buffer(offset,1),"Command Seq Num: " .. buffer(offset,1):uint())
        offset = offset + 1   
        datasubtree:add(buffer(offset,4),"Sector Addr= " .. buffer(offset,4):uint())
        offset = offset + 4   
        datasubtree:add(buffer(offset,4),"Number of sectors= " .. buffer(offset,4):uint())
     elseif  ( commandcode == 5 ) then
        datasubtree:add(buffer(offset,1),"Init1")
        offset = offset + 1
        datasubtree:add(buffer(offset,1),"Command Seq Num: " .. buffer(offset,1):uint())
        offset = offset + 1   
        datasubtree:add(buffer(offset,4),"Sector Addr= " .. buffer(offset,4):uint())
        offset = offset + 4   
        datasubtree:add(buffer(offset,4),"Number of sectors= " .. buffer(offset,4):uint())
    end
 
  end
    
  -- this is the response from the mem card]
  -- could probably be writted a bit better to reuse stuff but what the hell  
  if ( pinfo.src_port == 4096 ) then
    pinfo.cols.protocol = "mem004.rsp"
    -- Read CMD
    local slot = 1
    datasubtree = mem_top_subtree:add(buffer(offset,1),"Response")
    local commandcode = buffer(offset,1):uint()
    datasubtree:add(buffer(offset,1),"Response Code: " .. commandcode)
    
    
    if ( commandcode == 128 or commandcode == 130 or commandcode == 132 or commandcode == 133 or commandcode == 255) then
        if commandcode == 128 then
            datasubtree:add(buffer(offset,1),"ReadSts")
        elseif commandcode == 130 then
            datasubtree:add(buffer(offset,1),"Write")
        elseif commandcode == 132 then
            datasubtree:add(buffer(offset,1),"Init0")
        elseif commandcode == 133 then
            datasubtree:add(buffer(offset,1),"Init1")
        elseif commandcode == 255 then
            datasubtree:add(buffer(offset,1),"Bad")
        end
        offset = offset + 1
        datasubtree:add(buffer(offset,1),"Response Seq Num: " .. buffer(offset,1):uint())
        offset = offset + 1
        datasubtree:add(buffer(offset,2),"Mem Status= " .. memstatus(buffer(offset,2):uint()))
        -- memstatus subtree
        memstatussubtree = datasubtree:add(buffer(offset,2),"Mem Status")
        for i,v in ipairs (memstatus_verbose(buffer(offset,2):uint())) do
            memstatussubtree:add(buffer(offset,2),"Status= " .. v)
        end
        -- end
        offset = offset + 2
        datasubtree:add(buffer(offset,2),"Type Num= " .. "0x"..buffer(offset,2))
        offset = offset + 2
        
    elseif  ( commandcode == 129 ) then
        datasubtree:add(buffer(offset,1),"Read ")
        offset = offset + 1
        datasubtree:add(buffer(offset,1),"Response Seq Num: " .. buffer(offset,1):uint())
        offset = offset + 1   
        datasubtree:add(buffer(offset,2),"Mem Status= " .. memstatus(buffer(offset,2):uint()))
        -- memstatus subtree
        memstatussubtree = datasubtree:add(buffer(offset,2),"Mem Status")
        for i,v in ipairs (memstatus_verbose(buffer(offset,2):uint())) do
            memstatussubtree:add(buffer(offset,2),"Status= " .. v)
        end
        -- end
        offset = offset + 2
        datasubtree:add(buffer(offset,4),"Sector Addr= " .. "0x"..buffer(offset,4))
        offset = offset + 4
    end
    
    -- if ( search_for_zeros == true) then
       -- repeat
           -- block_zeros = string.rep("0",512)
           -- if ( syncword == "470100" or  syncword == "470101" or syncword == "474100" or syncword == "474101" or syncword == "471FFF" or syncword == "474000" or syncword == "475000"  ) then
               -- slotsubtree:append_text("Sync found at " .. offset)
           -- end
           -- offset = offset + 1
       -- until offset == 188
    -- end
        
        
    
  end
  
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(4097,mem_proto)
udp_table:add(4096,mem_proto)