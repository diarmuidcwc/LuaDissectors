local bit32 = require("bit32_compat")

-- AxonProtocol Analyser
-- declare our protocol
axon_proto = Proto("axon","Axon Backplane Protocol")
local axonf = axon_proto.fields
local ABI_MAPPING = {
	[0x0]="Register",
	[0x1]="EEPROM",
	[0x2]="ISP",
	[0x4]="No Ack",
}
local ABI_TYPE = {
	[0x0]="Sync",
	[0x1]="Timer",
	[0x2]="State",
	[0x3]="Read Request",
	[0x4]="Read Response",
	[0x5]="Programming",
	[0x6]="ISP",
	[0x7]="ACK",
	[0x8]="Data Scheduled",
	[0x9]="Data Unscheduled",
	[0xA]="Wrapped",
	[0xB]="Download",
	[0xC]="Command",

}

-- Declare a few fields
axonf.type = ProtoField.uint8("axon.type","Packet Type",base.HEX, ABI_TYPE, 0xFF )
axonf.dest = ProtoField.bytes("axon.dest", "Packet Destinations", base.NONE)
axonf.dest_slot = ProtoField.uint32("axon.dest.slot", "Packet Destination Slot", base.DEC, nil, 0xFC000000)
axonf.dest_subslot = ProtoField.uint32("axon.dest.subslot", "Packet Destination Sub-Slot", base.DEC, nil, 0x3000000)
axonf.dest_addr = ProtoField.uint32("axon.dest.addr", "Packet Destination Address", base.HEX, nil, 0xFFFFFF)
axonf.payload = ProtoField.bytes("axon.payload", "Packet Payload", base.NONE)
axonf.mapping = ProtoField.uint32("axon.mapping", "Mapping", base.DEC, ABI_MAPPING, 0x7)
axonf.clientid = ProtoField.uint32("axon.clientid", "Client ID", base.HEX, nil, 0xFFF8)
axonf.targetport = ProtoField.uint32("axon.targetport", "Target Port", base.DEC, nil, 0xFFFF0000)


-- Sync packet dissector

-- create a function to dissect it
axon_sync_proto = Proto("axonsync","Axon Sync")

function axon_sync_proto.dissector(buffer,pinfo,mtree)
	local offset = 0
	tree = mtree:add(buffer(offset),"Sync Packet ")
	
	--tree:add(buffer(offset,4), "Header " .. string.format("%08x",buffer(offset, 4):uint()))
	--offset = offset + 4
	tree:add(buffer(offset,4), "Time (s) " .. buffer(offset, 4):uint())
	offset = offset + 4
	tree:add(buffer(offset,4), "Time (ns) " .. buffer(offset, 4):uint())
	offset = offset + 4
	local v_frac = math.floor(buffer(offset, 4):uint() /16) -- right sbhift 4 bits
	tree:add(buffer(offset,4), "Time (fracns) " .. v_frac)
	offset = offset + 3
	local v_acc_ns = buffer(offset, 1):uint() % 0x10
	tree:add(buffer(offset,1), "Acc Time (ns) " .. v_acc_ns)
	offset = offset + 1
	local v_acc_fns = math.floor(buffer(offset, 4):uint() / 16)  -- right shift 4 bits
	tree:add(buffer(offset,4), "Acc Time (fracns) " .. v_acc_fns)
	offset = offset + 3
	local v_leap_sec =  ((buffer(offset, 1):uint() % 0x10) * 16) +  math.floor(buffer(offset+1, 1):uint() / 16)
	tree:add(buffer(offset,2), "Leap Seconds " .. v_leap_sec)
	offset = offset + 1
	local v_timewait_sync =  ((buffer(offset, 1):uint() % 0x10) * 16) + buffer(offset+1, 2):uint()
	tree:add(buffer(offset,3), "Wait Time After sync " .. v_timewait_sync)
	offset = offset + 3
	tree:add(buffer(offset,1), "Hard Adj Count " .. buffer(offset, 1):uint())
	offset = offset + 1
	local v_timesource =  math.floor(buffer(offset, 1):uint() / 16)
	tree:add(buffer(offset,1), "Time Source " .. v_timesource)
	local v_mode_acq =  ((buffer(offset, 1):uint() % 0x10) * 16) +  math.floor(buffer(offset+1, 1):uint() / 16)
	tree:add(buffer(offset,1), "Acq Mode " .. v_mode_acq)
	offset = offset + 1
	local v_in_sync =  (buffer(offset, 1):uint() % 0x2)
	tree:add(buffer(offset,1), "In sync " .. v_in_sync)
	offset = offset + 1
	tree:add(buffer(offset,4), "Digest " .. buffer(offset, 4):uint())
	offset = offset + 4
	tree:add(buffer(offset,6), "MAC Adress ".. tostring(buffer(offset, 6)):gsub("..", ":%0"):sub(2))
	offset = offset + 6
	tree:add(buffer(offset,4), "IP Adress " .. tostring(buffer(offset, 4):ipv4()))
	offset = offset + 4
	

end

--create a utility function for word extraction
function axon_getValue(buffer_range)
  return buffer_range: uint()
end

-- Break Out a Destination.
function axon_getDest(buffer_range)

    local destTable = {}
    local dest = axon_getValue(buffer_range)
    
    destTable.Slot = bit32.extract(dest, 26,6)
    destTable.SubSlot = bit32.extract(dest, 24,2)
    destTable.Address = bit32.extract(dest, 0, 24)

    return destTable
end

function axon_getClientInfo(range)

    local info = {}
    local client_info = axon_getValue(range)
    
    info.Mapping = bit32.extract(client_info, 0,3)
    info.ClientId = bit32.extract(client_info, 3, 13)
    info.TargetPort = bit32.extract(client_info, 16, 16)
    
    return info
end
    
function axon_showPRH(tree, range)

  local PRH = axon_getValue(range)
  local pingpong = bit32.extract(PRH,21,1)
  local destinations = bit32.extract(PRH,15,6)
  local revision = bit32.extract(PRH, 11,3)
  local scheduled = bit32.extract(PRH,10)
  local length = bit32.extract(PRH,0,10)
  
  local subtree = tree:add(range,string.format("%06x",PRH),"Packet Routing Header [PingPong: " .. pingpong .. " Destinations: "  .. destinations .. " Revision: " .. revision .. " Scheduled: " .. scheduled .. " Length: " .. length .. " words]")
  
  local info = {}
  info.Subtree = subtree
  info.DestinationCount = destinations
  info.PacketLength = length
  
  return info
end

function axon_showDest(tree,range)
    local dest = axon_getDest(range)
    tree:add(range, string.format("Response - Slot: %d, Subslot: %d, Address: %06x", dest.Slot, dest.SubSlot, dest.Address))

end

function axon_showClientInfo(tree,range)
    local info = axon_getClientInfo(range)
    tree:add(range, string.format("Mapping: %x, Client ID: %06x, Target Port: %d", info.Mapping, info.ClientId, info.TargetPort))
	tree:add(axonf.mapping, range)
	tree:add(axonf.clientid, range)
	tree:add(axonf.targetport, range)
end

--------------
---
----------------
abi_time_pkt = Proto("abitime", "ABI Time Packet")

local FLAGS_SOURCEID= {[0] ="RTC",
                       [1] ="Unreliable RTC - currently not supported",
                       [8] ="Analog IRIG-B, year from RTC or EEPROM",
                       [9] ="Digital IRIG-B, year from RTC or EEPROM",
                       [10]="Analog IRIG-B, year from IRIG stream",
                       [11]="Digital IRIG-B, year from IRIG stream",
                       [16]="GNSS: system is \"Automatic\" or \"Don't Know\"",
                       [17]="GNSS: GPS system",
                       [18]="GNSS: Galileo system",
                       [19]="GNSS: Glonass system",
                       [20]="GNSS: BeiDou system"
                   }

local FLAGS_HAVELEAP = {[0]="No Leap Second information", [1]="Leap Second Available"}
local FLAGS_HAVELOC = {[0]="No Local Time Source", [1]="Local Time Source Available"}
local FLAGS_ONCEOFF = {[0]="Continual Time Correction", [1]="Once Off Time Jump"}

local fs = abi_time_pkt.fields
-- Defined the fileds
fs.exttimepgmt = ProtoField.uint8("abitime.exttimefmt","Ext Time Format",base.HEX)
fs.exttimepscale = ProtoField.uint8("abitime.exttimefmt","Ext Time Scale",base.HEX)
fs.type = ProtoField.uint8("abitime.type","Type",base.HEX)
fs.exttime = ProtoField.uint64("abitime.exttime","ExtTime",base.DEC)
fs.exttimemsw = ProtoField.uint16("abitime.exttimemsw","ExtTime MSW",base.DEC)
fs.locns = ProtoField.uint32("abitime.locns","LocNS",base.DEC)
fs.locs = ProtoField.uint32("abitime.locs","LocS",base.DEC)
fs.locmarker = ProtoField.uint8("abitime.locs","Loc Marker",base.HEX)
fs.slot = ProtoField.uint8("abitime.slot","Slot",base.DEC)
--fs.subslot = ProtoField.uint8("abitime.subslot","Subslot",base.DEC)
fs.sourceid = ProtoField.uint8("abitime.sourceid","SourceID",base.DEC, FLAGS_SOURCEID, 0x1F)
fs.haveleapsec = ProtoField.uint8("abitime.haveleapsec","Have Leap Second",base.HEX, FLAGS_HAVELEAP, 0x20)
fs.haveloctime = ProtoField.uint8("abitime.haveloctime","Have LOC Time",base.HEX, FLAGS_HAVELOC, 0x40)
fs.onceoff = ProtoField.uint8("abitime.onceoff","OnceOff",base.HEX, FLAGS_ONCEOFF, 0x80)
fs.quality = ProtoField.uint8("abitime.quality","Quality",base.HEX, nil, 0xF)
fs.accuracy = ProtoField.uint8("abitime.accuracy","Accuracy",base.HEX)
fs.variance = ProtoField.uint16("abitime.variance","Variance",base.HEX)

function abi_time_pkt.dissector(buffer, pinfo, tree)
	local offset=8
	tree:add(fs.type, buffer(offset,1))
	offset = offset + 1
	tree:add(fs.exttimepgmt, buffer(offset,1), bit32.extract(buffer(offset,1):uint(), 0,2))
	tree:add(fs.exttimepscale, buffer(offset,1), bit32.extract(buffer(offset,1):uint(), 4, 2))	
	offset = offset + 1
	tree:add(fs.exttime, buffer(offset,8))
	ptptimesubtree = tree:add(buffer(offset,8),"PTPTimeStamp")
	ptptimesubtree:add(buffer(offset,4), "NanoSeconds: ", buffer(offset,2):uint() + buffer(offset+2,2):uint() * (2^16) )
	offset = offset + 4
	ptptimesubtree:add(buffer(offset,4),"Date: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset,2):uint() + buffer(offset+2,2):uint() * (2^16)))
	offset = offset + 4
	tree:add(fs.exttimemsw, buffer(offset,2))
	offset = offset + 2
	tree:add(fs.locns, buffer(offset,4), buffer(offset+2,2):uint()*256*256 + buffer(offset,2):uint())
	offset = offset + 4
	tree:add(fs.locs, buffer(offset,4), buffer(offset+2,2):uint()*256*256 + buffer(offset,2):uint())
	tree:add(buffer(offset,4),"LocalTime: " .. os.date("!%H:%M:%S %d %b %Y",buffer(offset,2):uint() + buffer(offset+2,2):uint() * (2^16)))
	offset = offset + 5
	tree:add(fs.locmarker, buffer(offset,1))
	offset = offset + 1
	tree:add(fs.sourceid, buffer(offset,1))
	tree:add(fs.haveleapsec, buffer(offset,1))
	tree:add(fs.haveloctime, buffer(offset,1))
	tree:add(fs.onceoff, buffer(offset,1))
	offset = offset + 1
	tree:add(fs.slot, buffer(offset,1), bit32.extract(buffer(offset,1):uint(), 2, 6))
--	tree:add(fs.subslot, buffer(offset,1), bit32.extract(buffer(offset,1):uint(), 0, 2))
	offset = offset + 1
	tree:add(fs.accuracy, buffer(offset,1))
	offset = offset + 1
	tree:add(fs.quality, buffer(offset,1))
	offset = offset + 1
	tree:add(fs.variance, buffer(offset,2))
	offset = offset + 2
	PID = {"P_Num", "P_Den", "I_Num", "I_Den", "D_Num", "D_Den"}
	local pid_subtree = tree:add(buffer(offset, 34), "PID Tree")
	for _, descr in ipairs(PID) do
		pid_subtree:add(buffer(offset,4), descr .. " = " .. buffer(offset,4):uint64())
		offset = offset + 4
	end
	pid_subtree:add(buffer(offset,4), "PID Scaling = " .. buffer(offset,4):uint64())
	offset = offset + 4
	pid_subtree:add(buffer(offset,4), "PID Acc Limit = " .. buffer(offset,4):uint64())
	offset = offset + 4
	pid_subtree:add(buffer(offset,2), "Leap Seconds = " .. buffer(offset,2):uint64())
	offset = offset + 2
	tree:add(buffer(offset,2), "Reserved")
	offset = offset + 2
	
end 

-- create a function to dissect it
function axon_proto.dissector(buffer,pinfo,tree)

  -- Packge Type Lookup
  local packetName = {}
  packetName[0x0] = "SYNC"
  packetName[0x1] = "Timer Accumulator"
  packetName[0x2] = "State"
  packetName[0x3] = "Read Request"
  packetName[0x4] = "Read Response"
  packetName[0x5] = "Programming"
  packetName[0x6] = "ISP"
  packetName[0x7] = "Acknowledgement"
  packetName[0x8] = "Data"
  packetName[0x9] = "External Time"
  packetName[0xA] = "Wrapped Ethernet"
  packetName[0xB] = "Memory Download"
  packetName[0xC] = "Command"
  packetName[0xD] = "Test"
  packetName[0xE] = "Test Response"
  
  udp_dst_f = pinfo.dst_port
  pinfo.cols.protocol = "ABI"
  
  local info_field = ""
  
  local typeNo = axon_getValue(buffer(3,1))
  local subtree
  if packetName[typeNo] == nil then
	topSubtree = tree:add(axon_proto,buffer(), "Axon (illegal type=" .. typeNo.. ") Packet")
  else
	topSubtree = tree:add(axon_proto,buffer(), "Axon " .. packetName[typeNo] .. " Packet")
  end
  
  local prhInfo = axon_showPRH(topSubtree, buffer(0,3))
  subtree = prhInfo.Subtree
  
  local offset = 3
  subtree = topSubtree:add(axonf.type, buffer(offset,1))
  
  offset = offset + 1

  subtree = topSubtree:add(axonf.dest, buffer(offset, 4 * prhInfo.DestinationCount))
  
  valid_parser = false
  
  local first_dest

  for d = 1, prhInfo.DestinationCount,1
  do
    local dest = axon_getDest(buffer(offset,4))
    if d == 1 then
        first_dest = dest
    end
    if dest.Slot == 63 then
        subtree:add(buffer(offset, 4), "Destination Slot: Broadcast (" .. dest.Slot .. ") Address: " .. string.format("%06x",dest.Address))
    elseif prhInfo.DestinationCount == 1 then
        subtree:add(buffer(offset, 4), "Destination Slot: " .. dest.Slot .. " SubSlot: " .. dest.SubSlot .. " Address: " .. string.format("%06x",dest.Address))
    else
        subtree:add(buffer(offset, 4), "Destination " .. d .. " - Slot: " .. dest.Slot .. " - SubSlot: " .. dest.SubSlot .. " Address: " .. string.format("%06x",dest.Address))
    end
	subtree:add(axonf.dest_slot,buffer(offset, 4))
	subtree:add(axonf.dest_subslot,buffer(offset, 4))
	subtree:add(axonf.dest_addr,buffer(offset, 4))
    offset = offset + 4
    
    -- for simulation I have reserved an address range for parser specific payloads
    if d == 1 and math.floor(dest.Address/65536) == 0xa then
        valid_parser = true 
    end
  end
  
  	if prhInfo.DestinationCount == 0 then
		subtree:add(buffer(offset, 4), "Destination Header Padding")
		offset = offset + 4
	end 

  local bodySize = ((prhInfo.PacketLength - 1) * 2) - offset;
  
  if buffer:len() < (offset + bodySize) then
	subtree = topSubtree:add(axonf.payload, buffer(offset, 2))
	topSubtree:add_expert_info(PI_MALFORMED,PI_WARN)
  else
	subtree = topSubtree:add(axonf.payload, buffer(offset, bodySize))
  end
  
  
  
  if typeNo == 2 then -- State Packet
    local state = axon_getValue(buffer(offset,2))
    local newstatestr = ""
    if state == 1 then
        newstatestr = "Acquisition Mode"
    elseif state == 2 then
        newstatestr = "Programming Mode"
    elseif state == 3 then
        newstatestr = "BIT Mode"
    elseif state == 4 then
        newstatestr = "ISP Mode"        
    elseif state == 5 then
        newstatestr = "Balance Mode"
    elseif state == 6 then
        newstatestr = "Low Power Mode"
    elseif state == 7 then
        newstatestr = "Soft Reset"
    else
        newstatestr = "Unknown Mode"
    end
    
    info_field = "Entering " .. newstatestr
    subtree:add(buffer(offset, 2),info_field);
  
  elseif typeNo == 3 then -- Read Request Packet
    local return_dest = axon_getDest(buffer(offset, 4))
    local info = axon_getClientInfo(buffer(offset + 4, 4))
    local respLen = axon_getValue(buffer(offset + 8, 4))
    
    subtree:add(buffer(offset, 4), string.format("Response - Slot: %d, SubSlot: %d, Address: %06x", return_dest.Slot, return_dest.SubSlot, return_dest.Address))
    subtree:add(buffer(offset + 4, 4), string.format("Mapping: %x, Client ID: %06x, Target Port: %d", info.Mapping, info.ClientId, info.TargetPort))
	subtree:add(axonf.mapping, buffer(offset + 4, 4))
	subtree:add(axonf.clientid, buffer(offset + 4, 4))
	subtree:add(axonf.targetport, buffer(offset + 4, 4))
    subtree:add(buffer(offset + 8, 4), string.format("Expected Response Length: %d words", respLen)) 
    if (bodySize-12) > 0 then
        subtree:add(buffer(offset + 12, bodySize - 12), string.format("Request Padding, Length: %d words", (bodySize-12)/2))
    end

    info_field = string.format("Slot: %d, Address: %06x, Expected Response Length: %d words", first_dest.Slot, first_dest.Address, respLen)
    
  elseif typeNo == 4 then -- Read Response Packet
    local info = axon_getClientInfo(buffer(offset, 4))
    subtree:add(buffer(offset, 4), string.format("Mapping: %x, Client ID: %06x, Target Port: %d", info.Mapping, info.ClientId, info.TargetPort))
	subtree:add(axonf.mapping, buffer(offset , 4))
	subtree:add(axonf.clientid, buffer(offset, 4))
	subtree:add(axonf.targetport, buffer(offset, 4))
    subtree:add(buffer(offset + 4, bodySize - 4), string.format("Response Data, Length: %d", (bodySize-4)/2))

    info_field = string.format("Data Length %d words", (bodySize-4)/2)
    
  elseif typeNo == 5 then -- Programming Packet
    axon_showDest(subtree, buffer(offset, 4))
    axon_showClientInfo(subtree, buffer(offset + 4, 4))
    subtree:add(buffer(offset + 8, bodySize - 8), string.format("Sector Data, Length %d", (bodySize-8)/2))

    info_field = string.format("Slot %d, Address: %06x, Data Length: %d words", first_dest.Slot, first_dest.Address, (bodySize-8)/2)
        
  elseif typeNo == 7 then -- Acknowledgement packet
    local info = axon_getClientInfo(buffer(offset, 4))
    local from_slot = axon_getValue(buffer(offset + 4, 2))
    subtree:add(buffer(offset, 4), string.format("Mapping: %x, Client ID: %06x, Target Port: %d", info.Mapping, info.ClientId, info.TargetPort))
	subtree:add(axonf.mapping, buffer(offset, 4))
	subtree:add(axonf.clientid, buffer(offset, 4))
	subtree:add(axonf.targetport, buffer(offset, 4))
    subtree:add(buffer(offset + 4, 2), string.format("Responding Slot: %d", from_slot))

    info_field = string.format("Slot: %d", from_slot)
    
  elseif typeNo == 6 then -- ISP Packet
    axon_showDest(subtree, buffer(offset, 4))
    axon_showClientInfo(subtree, buffer(offset + 4, 4))
    subtree:add(buffer(offset + 8, bodySize - 8), "ISP Payload")
	
  elseif typeNo == 0xC and first_dest.Slot == 0 and first_dest.Address == 0x2800 then -- Time packet (special command packet)
	timedissector = Dissector.get("abitime")
    timedissector:call(buffer(offset):tvb(),pinfo,subtree)

    local from_slot = bit32.extract(buffer(offset+31,1):uint(), 2, 6)
    info_field = string.format("Time Packet from slot: %d", from_slot)

  elseif typeNo == 0xC then -- Command Packet
    axon_showDest(subtree, buffer(offset, 4))
    axon_showClientInfo(subtree, buffer(offset + 4, 4))
    subtree:add(buffer(offset + 8, bodySize - 8), "Command Payload")
    
  elseif typeNo == 0xA then -- Wrapped Ethernet Packet
    local v_flags = buffer(offset, 2):uint()
	local v_odd_len = math.floor(v_flags % 2)
	local v_tx_ts_req = math.floor((v_flags / 2 ) % 2)
	local v_ts_present = math.floor((v_flags / 4 ) % 2)
	
	subtree:add(buffer(offset, 2), "Flags Field: 0x" .. buffer(offset, 2))
	subtree:add(buffer(offset, 2), "Odd Len = " .. v_odd_len)
	subtree:add(buffer(offset, 2), "TX Timestamp Req = " .. v_tx_ts_req)
	subtree:add(buffer(offset, 2), "Timestamp Present = " .. v_ts_present)
	
	if v_ts_present == 1 then
		subtree:add(buffer(offset+2, 4), "TimeStamp (s) " .. buffer(offset+2, 4):uint())
		subtree:add(buffer(offset+6, 4), "TimeStamp (ns) " .. buffer(offset+6, 4):uint())
		subtree:add(buffer(offset+10, bodySize-10-v_odd_len), "Wrapped Packet" )
	else
		subtree:add(buffer(offset+2, bodySize-2-v_odd_len), "Wrapped Packet" )
	end
    
  elseif typeNo == 8 then -- Data Packet
    if valid_parser == true then
      -- expecting parser abi packet
      axon_parserData(subtree, buffer(offset,-1), first_dest.Slot)
    end

    -- Include addressing detail in information field
	if first_dest == nil then
		info_field = ""
	else
		info_field = string.format("Slot %d, Address: %06x, Data Length: %d words", first_dest.Slot, first_dest.Address, (bodySize-8)/2)
	end
    
  elseif typeNo == 0 then -- Sync packet
	syncdissector = Dissector.get("axonsync")
    syncdissector:call(buffer(offset, 36):tvb(),pinfo,subtree)
  end
  
  offset = offset + bodySize
  
  local crc = buffer(offset,2): uint()
  subtree = topSubtree:add(buffer(offset, 2),"Packet CRC: " .. string.format("%04x",crc))
      
  -- Update the info field in the packet list pane
  if info_field == "" then
    pinfo.cols.info = packetName[typeNo]
  else
    pinfo.cols.info = packetName[typeNo] .. ", " .. info_field
  end

end


-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 
udp_table:add(3331,axon_proto)
udp_table:add(3332,axon_proto)
udp_table:add(3333,axon_proto)
udp_table:add(3334,axon_proto)
udp_table:add(3335,axon_proto)
udp_table:add(4000,axon_proto)


