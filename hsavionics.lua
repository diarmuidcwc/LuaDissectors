-- Wireshark dissector for High Speed Avionics bus
--

do
-- declare protocol
local hsavionics_proto = Proto("hsavionics","High Speed Avionics Bus")
local f = hsavionics_proto.fields

local LRU_FLAGS = {
  [0x00400000] = "PC_1",
  [0x00000001] = "PFD_1",
  [0x00000002] = "PFD_2",
  [0x00000004] = "MFD_1",
  [0x00000008] = "MFD_2",
  [0x00000100] = "GIA_1",
  [0x00000200] = "GIA_2",
  [0x00000400] = "GWX_1",
  [0x00000800] = "GDL69",
  [0x00001000] = "GSD_1",
  [0x00002000] = "GSD_2",
  [0x00000010] = "CDU_5",
  [0x00000020] = "CDU_6",
  [0x00000040] = "CDU_7",
  [0x00000080] = "CDU_8",
  [0x00004000] = "Reserved",
  [0x00008000] = "GDL59",
  [0x00800000] = "PC_2",
  [0x00C0FFFF] = "ALL",
  [0x000000FF] = "CDU",
  [0x00000300] = "GIA",
  [0x00003000] = "GSD",
  [0x008FFFFF] = "ALL except PC_1", -- i.e. PC_1 pinging out
  [0x00CFF7FF] = "ALL except GDL69", -- i.e. GDL69 pinging out
  [0x00001F07] = "Multiple", -- inferred
  [0x00000000] = "NONE" 
}
local PIPE_FLAGS = {
  [0x0] = "B Pipe",
  [0x1] = "C Pipe",
  [0x2] = "D Pipe",
  [0x3] = "D Debug Pipe",
  [0x4] = "hsavionics Manager Pipe",
  [0x5] = "Unknown Pipe 5",
  [0x6] = "Unknown Pipe 6",
  [0x7] = "Unknown Pipe 7",
  [0x8] = "Unknown Pipe 8",
  [0x9] = "Unknown Pipe 9",
  [0xA] = "Unknown Pipe 10",
  [0xB] = "Unknown Pipe 11",
  [0xC] = "Unknown Pipe 12",
  [0xD] = "Unknown Pipe 13",
  [0xE] = "Unknown Pipe 14",
  [0xF] = "Unknown Pipe 15"
}
local BOOL_FLAGS = {
  [0] = "False",
  [1] = "True"
}
f.dst = ProtoField.uint32('hsavionics.dst', 'Destination LRU', base.HEX, LRU_FLAGS)
f.src = ProtoField.uint32('hsavionics.src', 'Source LRU', base.HEX, LRU_FLAGS)
f.info = ProtoField.uint8('hsavionics.info', 'Info', base.HEX)
f.ack = ProtoField.uint8('hsavionics.info.ack', 'Ack', base.HEX,BOOL_FLAGS,0x80)
f.fin = ProtoField.uint8('hsavionics.info.fin', 'Fin', base.HEX,BOOL_FLAGS,0x40)
f.prd = ProtoField.uint8('hsavionics.info.prd', 'Prd', base.HEX,BOOL_FLAGS,0x20)
f.ping = ProtoField.uint8('hsavionics.info.ping', 'Ping', base.HEX,BOOL_FLAGS,0x10)
f.pipe = ProtoField.uint8('hsavionics.info.pipe', 'Pipe', base.HEX,PIPE_FLAGS,0xF)
f.frag_seq = ProtoField.uint8('hsavionics.frag_seq', 'Fragment Sequence', base.DEC)
f.seq_num = ProtoField.uint16('hsavionics.seq_num', 'Sequence Number', base.DEC)
f.size = ProtoField.uint16('hsavionics.size', 'Size of Data', base.DEC)
f.iop_id = ProtoField.uint16('hsavionics.iop.id', "ID", base.DEC)
f.iop_size = ProtoField.uint16('hsavionics.iop.size', "Size", base.DEC)
f.iop_valid = ProtoField.uint8('hsavionics.iop.valid', "Valid", base.HEX, BOOL_FLAGS, 0x01)
f.iop_priority = ProtoField.uint8('hsavionics.iop.priority', "Priority", base.DEC)


function lru_name(address)
  --Note: reordered to place common values first (for efficiency)
  if     address == 0x400000 then return "PC_1"
  elseif address == 0x000001 then return "PFD_1"
  elseif address == 0x000002 then return "PFD_2"
  elseif address == 0x000004 then return "MFD_1"
  elseif address == 0x000008 then return "MFD_2"
  elseif address == 0x000100 then return "GIA_1"
  elseif address == 0x000200 then return "GIA_2"
  elseif address == 0x000400 then return "GWX_1"
  elseif address == 0x000800 then return "GDL69"
  elseif address == 0x001000 then return "GSD_1"
  elseif address == 0x002000 then return "GSD_2"
  elseif address == 0x000010 then return "CDU_5"
  elseif address == 0x000020 then return "CDU_6"
  elseif address == 0x000040 then return "CDU_7"
  elseif address == 0x000080 then return "CDU_8"
  elseif address == 0x004000 then return "Reserved"
  elseif address == 0x008000 then return "GDL59"
  elseif address == 0x800000 then return "PC_2"
  elseif address == 0xC0FFFF then return "ALL"
  elseif address == 0x0000FF then return "CDU"
  elseif address == 0x000300 then return "GIA"
  elseif address == 0x003000 then return "GSD"
  elseif address == 0x8FFFFF then return "ALL except PC_1" -- i.e. PC_1 pinging out
  elseif address == 0xCFF7FF then return "ALL except GDL69" -- i.e. GDL69 pinging out
  elseif address == 0x001F07 then return "Multiple" -- inferred
  elseif address == 0x000000 then return "NONE"
  else return string.format("%08x", address)
  end
end

-- create function to dissect it
function hsavionics_proto.dissector(buffer,pinfo,tree)
  pinfo.cols.protocol = "hsavionics"

  --local udp_table = DissectorTable.get("udp.port")

  --
  -- HWM hsavionics (present in every hsavionics packet)
  --

  -- Extract information from buffer
  local hwm_dst = buffer(0,4):le_uint()
  local hwm_dst_string = lru_name(hwm_dst) .. string.format(" (%08x)", hwm_dst)
  local hwm_src = buffer(4,4):le_uint()
  local hwm_src_string = lru_name(hwm_src) .. string.format(" (%08x)", hwm_src)
  local hwm_info = buffer(8,1):uint()
  local ping = math.floor((hwm_info /16) %2)
  local prd = math.floor((hwm_info /32) %2)
  local fin = math.floor((hwm_info /64) %2)
  local ack = math.floor((hwm_info /128) %2)
  local pipe = hwm_info % 16
  local pipe_string
  if     pipe == 0 then pipe_string = "B Pipe"
  elseif pipe == 1 then pipe_string = "C Pipe"
  elseif pipe == 2 then pipe_string = "D Pipe"
  elseif pipe == 3 then pipe_string = "D Debug Pipe"
  elseif pipe == 4 then pipe_string = "hsavionics Manager Pipe"
  else                  pipe_string = "Unknown Pipe"
  end
  local info_string = string.format("Ack:%x Fin:%x Prd:%x Ping:%x Pipe:%x", ack, fin, prd, ping, pipe)
  local frag_seq = buffer(10,1):uint()

  -- Create hsavionics tree
  local hwm_subtree = tree:add(hsavionics_proto,buffer(0,16),"hsavionics HWM, Dst: " .. hwm_dst_string .. ", Src: " .. hwm_src_string .. ", " .. info_string)
  local offset = 0
  hwm_subtree:add_le(f.dst,buffer(offset,4))
  offset = offset + 4
  hwm_subtree:add_le(f.src,buffer(offset,4))
  offset = offset + 4
  do
    -- info_subtree is dummy level of hierarchy to keep bitfields together
    local info_subtree = hwm_subtree:add(buffer(offset,1), info_string .. ", " .. pipe_string .. ":" .. pipe)--  .. buffer(offset,1) .. ")")
    info_subtree:add(f.ack,buffer(offset,1))
    info_subtree:add(f.fin,buffer(offset,1))
    info_subtree:add(f.prd,buffer(offset,1))
    info_subtree:add(f.ping,buffer(offset,1))
    info_subtree:add(f.pipe,buffer(offset,1))
    offset = offset + 1
  end
  --(2 bytes reserved)
  offset = offset + 1
  hwm_subtree:add_le(f.frag_seq,buffer(offset,1))
  offset = offset + 1
  --(2 bytes reserved)
  offset = offset + 1
  hwm_subtree:add_le(f.seq_num,buffer(offset,2))
  offset = offset + 2
  local hwm_data_size = buffer(offset,2):le_uint()
  hwm_subtree:add_le(f.size,buffer(offset,2))
  offset = offset + 2

  pinfo.cols.info = "Dst: " .. hwm_dst_string .. ", Src: " .. hwm_src_string
  pinfo.cols.info:append (", " .. pipe_string)

  if ping == 1 then
    --
    -- hsavionics Ping and Ping Response
    --

    --if hwm_data_size != 5 then
      --error
    --end
    local num_transmits = buffer(offset,1)
    local timestamp = buffer(offset+1,4):le_uint()
    local ping_subtree
    if ack == 1 then
      pinfo.cols.info:append (", Ping Response")
      ping_subtree = tree:add(buffer(offset,hwm_data_size),"hsavionics Ping Ack, Transmits: " .. (num_transmits) .. ", Timestamp: " .. timestamp)
    else
      pinfo.cols.info:append (", Ping Request")
      ping_subtree = tree:add(buffer(offset,hwm_data_size),"hsavionics Ping, Transmits: " .. tostring(num_transmits) .. ", Timestamp: " .. timestamp)
    end
    ping_subtree:add(buffer(offset,1),"Number of transmits:" .. tostring(buffer(offset,1):uint()))
    offset = offset + 1
    ping_subtree:add(buffer(offset,4),"Timestamp:"  .. tostring(buffer(offset,4):le_uint()))
    offset = offset + 4


  elseif ack == 1 then
    --
    -- hsavionics Ack
    --


    --if hwm_data_size != 5 then
      --error
    --end
    pinfo.cols.info:append (", Ack")

  elseif frag_seq > 1 then
    if fin == 1 then
      pinfo.cols.info:append (", Final Fragment, Sequence = " .. frag_seq)
      local iop_subtree = tree:add(buffer(offset,hwm_data_size),"Final Fragment, Sequence: " .. frag_seq)
    else
      pinfo.cols.info:append (", Fragment, Sequence = " .. frag_seq)
      local iop_subtree = tree:add(buffer(offset,hwm_data_size),"Continuation Fragment, Sequence: " .. frag_seq)
    end

  else

    --
    -- IOP hsavionics
    --

    local iop_index = 0
    local data_left = hwm_data_size

    repeat
      -- per IOP
      local iop_id = tostring(buffer(offset,2):le_uint())
      local iop_size = buffer(offset+2,2):le_uint()

      local data_size
      local iop_subtree
      if iop_size+8 > data_left then
        data_size = data_left
        iop_subtree = tree:add(buffer(offset,data_size),"IOP " .. iop_index .. " (fragment), ID: " .. iop_id .. ", Data Size: " .. iop_size)
      else
        data_size = iop_size + 8
        iop_subtree = tree:add(buffer(offset,data_size),"IOP " .. iop_index .. ", ID: " .. iop_id .. ", Data Size: " .. iop_size)
      end
      iop_subtree:add_le(f.iop_id,buffer(offset,2))
      offset = offset + 2
      iop_subtree:add_le(f.iop_size,buffer(offset,2))
      offset = offset + 2
      iop_subtree:add(f.iop_valid,buffer(offset,1)):set_text("Valid: " .. tostring(buffer(offset,1):le_uint()))
      offset = offset + 1
      iop_subtree:add(f.iop_priority,buffer(offset,1))
      offset = offset + 1
      --(2 bytes reserved)
      offset = offset + 2
      iop_subtree:add(buffer(offset,data_size-8),"Data:" .. tostring(buffer(offset,data_size-8)))
      offset = offset + iop_size
      data_left  = data_left - iop_size - 8
      iop_index = iop_index + 1
    until data_left <= 8
    if data_left > 0 then
      local iop_subtree = tree:add(buffer(offset,data_left),"Trailing bytes: " .. data_left)
      iop_subtree:add(buffer(offset,data_left),"Data:" .. tostring(buffer(offset,data_left)))
    end

    if frag_seq == 1 then
      pinfo.cols.info:append (", Initial Fragment, Sequence = 1")
    end
    pinfo.cols.info:append (", " .. iop_index .. " IOPs")
  end

end

-- register protocol to handle UDP port 5001-5004,6001-6004 mentioned in Garmin spec
-- load the udp.port table (UDP ports are quoted as decimal)
udp_table = DissectorTable.get("udp.port")
udp_table:add(6001,hsavionics_proto)
udp_table:add(6002,hsavionics_proto)
udp_table:add(6003,hsavionics_proto)
udp_table:add(6004,hsavionics_proto)
udp_table:add(5001,hsavionics_proto)
udp_table:add(5002,hsavionics_proto)
udp_table:add(5003,hsavionics_proto)
udp_table:add(5004,hsavionics_proto)
udp_table:add(1173,hsavionics_proto)

-- Also load for Embedded protocol. EtherType=0x6009 (note specify in hex)
eth_table = DissectorTable.get("ethertype")
eth_table:add(0x6009,hsavionics_proto)

end
