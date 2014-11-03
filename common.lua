
-------------------------------------------------------
-- ~These are some commonly used functions in my disector
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

function sbi_to_walltime(sbitime)
  local usec = string.sub(sbitime,-6)
  local seconds = string.sub(sbitime,-8,-7)
  if ( string.find(string.sub(sbitime,-9,-9), "%a") ) then
    -- there was hex in the mins then we return with 0
    return 0
  end
  local mins = string.sub(sbitime,-9,-9) + (tonumber(string.sub(sbitime,-10,-10),16) % 8 )*10
  local raw_hrs = math.floor(tonumber(string.sub(sbitime,-10,-10),16)*2/16) + tonumber(string.sub(sbitime,-11,-11),16)*2
  local hrs = raw_hrs%16 + math.floor(raw_hrs/16)*10
  -- because we are gmt + 1 I need to add an hr
  --hrs = hrs + 1
  local vyear = os.date("%Y");
  local vmonth = os.date("%m")
  local vday = os.date("%d")
  local localtime = os.time{year=vyear,month=vmonth,day=vday,hour=hrs,min=mins,sec=seconds}
  return localtime
end


function info_to_txt(infoword)
  local info_txt = "NEW"
  local trunc_word = math.floor(infoword/16)
  if (math.floor(trunc_word/8) >= 1 ) then
    info_txt = "EMPTY"
  elseif (math.floor(trunc_word/4) >= 1) then
    info_txt = "STALE"
  elseif (math.floor(trunc_word/2) >= 1) then
    info_txt = "SKIPPED"
  end
  return info_txt
end


function format_ip(ipstring)
  _,_,ip1,ip2,ip3,ip4 = string.find(ipstring,"(%a%a)(%a%a)(%a%a)(%a%a)")
  local return_value = ipstring
  --local return_value = ip1..ip2..ip3..ip4
  --local return_value = tonumber(ip1)..tonumber(ip2)..tonumber(ip3)..tonumber(ip4)
  return return_value
end

function format_mac_address(macstring)
  local mac_address = string.gsub(macstring,"(%a%a)(%a%a)(%a%a)(%a%a)(%a%a)(%a%a)","%1-%2-%3-%4-%5-%6")
  return mac_address
end


	
-- reverses a table
function reverse(t)
  local nt = {} -- new table
  local size = #t + 1
  for k,v in ipairs(t) do
    nt[size - k] = v
  end
  return nt
end

-- converts a number to a table of bits
function tobits(num)
    local t={}
    -- for i=0,15 do
        -- t[i] = 0
    -- end
    
    while num>0 do
        rest=num%2
        t[#t+1]=rest
        num=(num-rest)/2
    end

    --t = reverse(t)
    return t
    --return table.concat(t)
end

-- returns just the table of bits as a string
function memstatus(status)
    return table.concat(reverse(tobits(status)))
end

-- this interpreted the table of bits and returns a
-- table of strings with the bits explained

function memstatus_verbose(status)
    -- get the bit table
    bit_table = tobits(status)
    -- the table we will return
    string_array = {}
    -- lua arrays are indexed from 1 so the index here
    -- are one more than in the SID
    if ( bit_table[9] == 1 ) then
        table.insert(string_array,"Timeout")
    end
    if ( bit_table[10] == 1 ) then
        table.insert(string_array,"Logging Stopped")
    end
    if ( bit_table[12] == 1 ) then
        table.insert(string_array,"MEM Initializating")
    end
    if ( bit_table[13] == 1 ) then
        table.insert(string_array,"Card Fault")
    end
    if ( bit_table[14] == 1 ) then
        table.insert(string_array,"Bad Command")
    end
    if ( bit_table[15] == 1 ) then
        table.insert(string_array,"Read Successful")
    end
    if ( bit_table[16] == 1 ) then
        table.insert(string_array,"Write Successful")
    end  
	if (status % 16 ~= 0) then
		remaining_count = 6.25 * (status % 16)
		table.insert(string_array,"Remaining Init Count = "..remaining_count.."%")
    end  
    return string_array
	--return bit_table
end

-- this interpreted the table of bits and returns a
-- table of strings with the bits explained

function swistatus_verbose(status)
    -- get the bit table
    bit_table = tobits(status)
    -- the table we will return
    string_array = {}
    -- lua arrays are indexed from 1 so the index here
    -- are one more than in the SID
    if ( bit_table[1] == 1 ) then
        table.insert(string_array,"Port 1 Not Connected")
    end
    if ( bit_table[2] == 1 ) then
        table.insert(string_array,"Port 2 Not Connected")
    end
    if ( bit_table[3] == 1 ) then
        table.insert(string_array,"Port 3 Not Connected")
    end
    if ( bit_table[4] == 1 ) then
        table.insert(string_array,"Port 4 Not Connected")
    end
    if ( bit_table[5] == 1 ) then
        table.insert(string_array,"Port 1 Half Duplex")
    end
    if ( bit_table[6] == 1 ) then
        table.insert(string_array,"Port 2 Half Duplex")
    end
    if ( bit_table[7] == 1 ) then
        table.insert(string_array,"Port 3 Half Duplex")
    end
    if ( bit_table[8] == 1 ) then
        table.insert(string_array,"Port 4 Half Duplex")
    end    
    return string_array
    --return bit_table
end


function bcu145_report_verbose(status)
    -- get the bit table
    bit_table = tobits(status)
    -- the table we will return
    string_array = {}
    -- lua arrays are indexed from 1 so the index here
    -- are one more than in the SID

    if ( bit_table[1] == 1 ) then
        table.insert(string_array,"Out of Synch")
    end
    if ( bit_table[2] == 1 ) then
        table.insert(string_array,"Time Sync Lost")
    end
    if ( bit_table[5] == 1 ) then
        table.insert(string_array,"Module Reset")
    end
    if ( bit_table[7] == 1 ) then
        table.insert(string_array,"RX Overflow")
    end
    if ( bit_table[8] == 1 ) then
        table.insert(string_array,"RX Error")
    end
    if ( bit_table[9] == 1 ) then
        table.insert(string_array,"Invalid Configuration")
    end
    if ( bit_table[12] == 1 ) then
        table.insert(string_array,"Eth Link 0 Down")
    end
    if ( bit_table[13] == 1 ) then
        table.insert(string_array,"Eth Link 1 Down")
    end
    if ( bit_table[16] == 1 ) then
        table.insert(string_array,"Event")
    end  
    return string_array
	--return bit_table
end