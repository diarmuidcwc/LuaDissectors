-- 
-- This dissects the temperature reported from the BCU

bcutemperature_proto = Proto("bcutemperature","BCU 140 Temperature")
-- Declare a few fields that we are in
f_bcutemperature = ProtoField.float("bcutemperature.temperature","Temperature",base.DEC)
bcutemperature_proto.fields = {f_bcutemperature}

-- create a function to dissect it
function bcutemperature_proto.dissector(buffer,pinfo,tree)

	pinfo.cols.protocol = "bcutemperature"
	--local datasubtree = tree:add(bcutemperature_proto,buffer(),"BCU Temperature")	
	local reading = buffer(0,4):int()
	local temp = (reading / 1000)
	tree:add(f_bcutemperature,buffer(0,4),temp)
end