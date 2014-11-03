function numberstring(number, base)
   local s = ""
   repeat
      local remainder = mod(number,base)
      s = digits[remainder]..s
      number = (number-remainder)/base
   until number==0
   return s
end

-- trivial protocol example
-- declare our protocol
iena_proto = Proto("iena","IENA Protocol")
-- create a function to dissect it
function iena_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "iena"
    local iena_top_subtree = tree:add(iena_proto,buffer(),"IENA Protocol Data")
	local packets_per_slot = 28
	subtree = iena_top_subtree:add(buffer(0,13),"IENA Header")
	subtree:add(buffer(0,2),"IENA Key: " .. tostring(buffer(0,2)))
	subtree:add(buffer(2,2),"Size: " .. buffer(2,2):uint())
	local iena_size_in_words = buffer(2,2):uint()
	--subtree:add(buffer(4,6),"Time: " .. tostring(buffer(4,6)))
	--subtree:add(buffer(10,1),"Key Status: " .. tostring(buffer(10,1)))
	--subtree:add(buffer(11,1),"N2 Status: " .. tostring(buffer(11,1)))
	--subtree:add(buffer(12,2),"Seq Number: " .. buffer(12,2):uint())
	local number_of_slots = ((iena_size_in_words * 2) - 16)/packets_per_slot
    subtree = iena_top_subtree:add(buffer(14,(iena_size_in_words*2-16)),"CBM104 Data")
	local offset = 14
	local slot = 0
	repeat
		slot = slot + 1
		local slottree = subtree:add(buffer(offset,packets_per_slot),"Slot - ")
		--slottree:add(buffer(offset,2),"Read Count: "               .. buffer(offset,2):uint())
		slottree:add(buffer(offset,2),"Read Count: "               .. buffer(offset,2):uint())
		offset = offset + 2;
		slottree:add(buffer(offset,2),"Expected Open Slot: "    .. tostring(buffer(offset,2)))
		offset = offset + 2;
		local msg_info = buffer(offset,1):uint()
		msg_info = math.floor(msg_info/2) * 2 -- remove the lsb
		if msg_info == 0 then
			slottree:add(buffer(offset,1),"New Data")
			slottree:append_text(" - New Data")
		elseif msg_info > 127 then
			slottree:add(buffer(offset,1),"Empty Slot")
			slottree:append_text(" - Empty")
		elseif msg_info > 63 then
			slottree:add(buffer(offset,1),"Stale Slot")
			slottree:append_text(" - Stale Data")
		else
			slottree:add(buffer(offset,1),"Skipped Slot")
			slottree:append_text(" - Skipped Data")
		end
		slottree:add(buffer(offset,1),"Slot Info: "        .. tostring(buffer(offset,1)))
		offset = offset + 1;
		local actual_open_slot = buffer(offset,1):uint()
		slottree:add(buffer(offset,1),"Actual Open Slot: "    .. tostring(buffer(offset,1)))
    slottree:append_text(tostring(buffer(offset,1)))
		offset = offset + 1;
		slottree:add(buffer(offset,2),"Time Hi: "                   .. buffer(offset,2):uint())
		offset = offset + 2;
		slottree:add(buffer(offset,2),"Time Lo: "                   .. buffer(offset,2):uint())
		offset = offset + 2;
		slottree:add(buffer(offset,2),"Time Mu: "                   .. buffer(offset,2):uint())
		offset = offset + 2;
		slottree:add(buffer(offset,2),"Message Count: "             .. buffer(offset,2):uint())
		offset = offset + 2;
		slottree:add(buffer(offset,2),"Message Size: "              .. buffer(offset,2):uint())
		offset = offset + 2;
		slottree:add(buffer(offset,2),"Message Error: "              .. buffer(offset,2):uint())
		offset = offset + 2;
		slottree:add(buffer(offset,1),"Slot Addr: "        .. tostring(buffer(offset,1)))
		offset = offset + 1;
		slottree:add(buffer(offset,1),"Slot Status: "      .. tostring(buffer(offset,1)))
		offset = offset + 1;
		slottree:add(buffer(offset,2),"Slot Data 1: "      .. tostring(buffer(offset,2)))
		offset = offset + 2;
		slottree:add(buffer(offset,2),"Slot Data 2: "      .. tostring(buffer(offset,2)))
		offset = offset + 2;
		slottree:add(buffer(offset,2),"Slot Data 3: "      .. tostring(buffer(offset,2)))
		offset = offset + 2;
		slottree:add(buffer(offset,2),"Report: "      .. tostring(buffer(offset,2)))
		offset = offset + 2;
	until slot == number_of_slots
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(1023,iena_proto)