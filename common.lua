
-------------------------------------------------------
-- ~These are some commonly used functions in my disector
-------------------------------------------------------

-- Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuidcwc/LuaDissectors




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
  hrs = hrs + 1
  local vyear = os.date("%Y");
  local vmonth = os.date("%m")
  local vday = os.date("%d")
  local localtime = os.time{year=vyear,month=vmonth,day=vday,hour=hrs,min=mins,sec=seconds}
  return localtime
end

currentyear = os.date("%Y", os.time())
seconds_since_epoch = os.time{year=currentyear, month=1, day=1, hour=0, min=0, sec=0}

function rtc_to_localtime(buffer)
    rtc_upper = buffer(4,2):le_uint()
    rtc_time = buffer(0,4):le_uint() + rtc_upper*4294967296
	local rtc_in_100ns = tonumber(rtc_time)
	local time_in_sec = rtc_in_100ns *100 / 1e9
	local sec = math.floor(time_in_sec)
	local nsec = (time_in_sec % 1) * 1e9
	local datestr = os.date("!%H:%M:%S %d %b %Y" , sec )
	return string.format("Seconds = %s Nanoseconds = %d Date= %s",  sec, nsec, datestr)
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

function progstats_verbose(status)
    -- get the bit table
    bit_table = tobits(status)
    -- the table we will return
    string_array = {}
    -- lua arrays are indexed from 1 so the index here
    -- are one more than in the SID
    if ( bit_table[4] == 1 ) then
        table.insert(string_array,"Go")
    end
    if ( bit_table[5] == 1 ) then
        table.insert(string_array,"BIST Enable")
    end
    if ( bit_table[6] == 1 ) then
        table.insert(string_array,"Port B")
    end
    if ( bit_table[7] == 1 ) then
        table.insert(string_array,"Request ACK")
    end
    if ( bit_table[8] == 1 ) then
        table.insert(string_array,"BurstData")
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

function reverse_byte_bit_order(byte)

  --note: array ordering starts from 1 in lua, so need to pass in byte + 1
  local reverse = {
    0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, --   0 -   8
    0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0, --   9 -  15
    0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8, --  16 -  23
    0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8, --  24 -  31
    0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4, --  32 -  39
    0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4, --  40 -  47
    0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec, --  48 -  55
    0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc, --  56 -  63
    0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2, --  64 -  71
    0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2, --  72 -  79
    0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea, --  80 -  87
    0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa, --  88 -  95
    0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6, --  96 - 103
    0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6, -- 104 - 111
    0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee, -- 112 - 119
    0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe, -- 120 - 127
    0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1, -- 128 - 135
    0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1, -- 136 - 143
    0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9, -- 144 - 151
    0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9, -- 152 - 159
    0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5, -- 160 - 167
    0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5, -- 168 - 175
    0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed, -- 176 - 183
    0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd, -- 184 - 191
    0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3, -- 192 - 199
    0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3, -- 200 - 207
    0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb, -- 208 - 215
    0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb, -- 216 - 223
    0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7, -- 224 - 231
    0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7, -- 232 - 239
    0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef, -- 240 - 247
    0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff, -- 248 - 255
    0x00
  }
  return reverse[byte]
end

function parse_arinc_detail(byte1,byte2,byte3,byte4) -- (message is 4 bytes)
  -- Usage: parse_arinc_detail(buffer(offset,4))
  --local byte1 = msgdata(0,1):uint() --/ (256*256*256))
  --local byte2 = msgdata(1,1):uint() --/ (256*256)    ) % 256
  --local byte3 = msgdata(2,1):uint() --/ (256)        ) % 256
  --local byte4 = msgdata(3,1):uint() --               ) % 256
  local parity = byte1 / 128
  local ssm = byte1/32 % 4
  local data = ((byte1 % 32) * 256 + byte2 ) * 64 + (byte3 / 4)
  local sdi = byte3 % 4
  local label = reverse_byte_bit_order(byte4+1)
  return string.format(" Label: %03o Par:%01x SSM:%01x Data:%05x SDI:%01x", label, parity, ssm, data, sdi)
end

function arinc_raw(message) -- (message is 4 bytes)
  byte1 = message(0,1):uint()
  byte2 = message(1,1):uint()
  byte3 = message(2,1):uint()
  byte4 = message(3,1):uint()
  return string.format(" %02x %02x %02x %02x",byte1, byte2, byte3, byte4)
end

function endian_swap(buffer)
    -- There might be a better way to do this but it takes a bytearry
    -- and does an endian swap on it. Used for some buffers in chapter 10
    local blen = buffer:len()
    local new_buf  = ByteArray.new()
    new_buf:set_size(blen)
    for i=0,blen-1,2 do
        new_buf:set_index(i, buffer:get_index(i+1))
        new_buf:set_index(i+1, buffer:get_index(i))
    end
    return new_buf
end