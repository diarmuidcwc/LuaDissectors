-- 
-- This dissects the temperature reported from the BCU

trfgen_proto = Proto("trfgen","Traffic Gen")
-- Declare a few fields that we are in
f_report = ProtoField.uint32("trfgen.report","Report",base.HEX)
f_rxframecount = ProtoField.uint32("trfgen.rxframecount","rxframecount",base.DEC)
f_rxdropcount = ProtoField.uint32("trfgen.rxdropcount","rxdropcount",base.DEC)
f_rxerrcount = ProtoField.uint32("trfgen.rxerrcount","rxerrcount",base.DEC)
f_rxdiscardcount = ProtoField.uint32("trfgen.rxdiscardcount","rxdiscardcount",base.DEC)
f_phymode = ProtoField.uint32("trfgen.phymode","phymode",base.HEX)
f_gmiirxerror = ProtoField.uint32("trfgen.gmiirxerror","gmiirxerror",base.HEX)
f_framecount = ProtoField.uint32("trfgen.framecount","gmiirxerror",base.DEC)
f_config = ProtoField.uint32("trfgen.config","config",base.HEX)
trfgen_proto.fields = {f_report,f_rxframecount,f_rxdropcount,f_rxerrcount,f_rxdiscardcount,f_phymode,f_gmiirxerror,f_framecount,f_config}

-- create a function to dissect it
function trfgen_proto.dissector(buffer,pinfo,tree)

	pinfo.cols.protocol = "trfgen"
	local offset=0
	tree:add(f_report,buffer(offset,2))
	offset = offset+2
	tree:add(f_rxframecount,buffer(offset,2))
	offset = offset+2
	tree:add(f_rxdropcount,buffer(offset,2))
	offset = offset+2
	tree:add(f_rxerrcount,buffer(offset,2))
	offset = offset+2
	tree:add(f_rxdiscardcount,buffer(offset,2))
	offset = offset+2
	tree:add(f_phymode,buffer(offset,2))
	offset = offset+2
	tree:add(f_gmiirxerror,buffer(offset,2))
	offset = offset+2
	tree:add(f_framecount,buffer(offset,2))
	offset = offset+2
	tree:add(f_config,buffer(offset,2))
	
end