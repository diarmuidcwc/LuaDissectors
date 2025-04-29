-- IRIG106 Chapter 10 file parser. Very rudimentary support for the file format

local IRIG106 = FileHandler.new("IRIG106", "lua_ch10", "IRIG106 Chapter 10/11 Packet Reader","r")


local dprint = function(...)
    print(table.concat({"Lua:", ...}," "))
end

-- Register file handler
function IRIG106.read_open(filename, fileinfo)
    return true
end

function IRIG106.read_close(file, cinfo)
    return true
end


-- Read a record (Chapter 10 packet)
function IRIG106.read(file, cinfo, finfo)
    local pos = file:seek("cur")

    local header = file:read(24)
    if not header or #header < 24 then return nil end

    local sync = string.unpack("<H", header)
    if sync ~= 0xEB25 then return nil end

    -- Extract length from packet header
    local packet_length = string.unpack("<I", header, 5)
    local full_packet = header .. file:read(packet_length - 24)
    --local rtc_time = string.unpack("<I6", header, 17)
    --local rtc_time_ns = rtc_time * 100
    --local rtc_seconds = math.floor(rtc_time_ns / 1e9)
    --local rtc_nseconds = math.fmod(rtc_time_ns, 1e9)
    --dprint(rtc_seconds)
    if #full_packet ~= packet_length then return nil end

    finfo.original_length = #full_packet
    finfo.captured_length = #full_packet
    finfo.data = full_packet
    --finfo.time = NSTime(rtc_seconds, rtc_nseconds)
    finfo.time = NSTime(0, 0)
    finfo.encap = wtap_encaps.USER0

    cinfo.time_precision = wtap_filetypes.TSPREC_NSEC
    
    return pos
end
IRIG106.extensions = "ch10" -- this is just a hint

-- Register the reader with Wireshark
register_filehandler(IRIG106)
