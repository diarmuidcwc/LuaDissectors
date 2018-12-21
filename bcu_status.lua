-- 
-- This protocol dissector pulls out the BCU Report word and creates some 
-- boolean fields from it. so we can find all the Error events using it

bcu_status_proto = Proto("bcureport","BCU140 Control Word")

-- Declare a few fields that we are in
status_table_lookup = {[1]="OutOfSync",[2]="TimeSourceLost",[3]="FramingEngCVTOverflow",[4]="RAMError",[5]="CPUReboot",[7]="RXOverflow",[8]="UnexpectedRXFrame",[16]="Event"}
local status_fields = {}
for i,v in pairs(status_table_lookup) do
	status_fields[i] = ProtoField.bool("bcureport."..v)
end
bcu_status_proto.fields = status_fields

-- create a function to dissect it
function bcu_status_proto.dissector(buffer,pinfo,tree)

	pinfo.cols.protocol = "bcureport"
	local datasubtree = tree:add(bcu_status_proto,buffer(),"Controller Status")
	local offset=12 -- skip the first bytes as we are not too interested at the moment
	
	datasubtree:add(buffer(offset,2),"Controller Status: " .. buffer(offset,2))	
	for i,v in ipairs (tobits(buffer(offset,2):uint())) do
		if v == 1 then
			datasubtree:add(status_fields[i],buffer(offset,2))
		end 
		
	end
	if (pinfo.len == 98) then
		offset = offset + 10 -- skip DOY and other stuff
	else
		offset = offset + 4 -- skip DOY
	end
	local sbi_time = tostring(buffer(offset,6))
	local usec = string.sub(sbi_time,-6)
	local wall_time = sbi_to_walltime(sbi_time)
	tree:add(buffer(offset,6),"BCU_Time (ptp equivalent): " .. os.date("%!%H:%M:%S",wall_time+35))
    offset = offset + 4 -- just get usec
	tree:add(buffer(offset,2),"BCU_usec: " .. usec)
end