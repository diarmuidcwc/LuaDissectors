
enc106_pll_proto = Proto("enc106_pll","enc106 PLL")
-- Declare a few fields that we are in

f_cnt1 = ProtoField.uint16("enc106_pll.counter1","Counter 1",base.DEC)
f_cnt2 = ProtoField.uint16("enc106_pll.counter2","Counter 2",base.DEC)

enc106_pll_proto.fields = {f_cnt1,f_cnt2}

function enc106_pll_proto.dissector(buffer,pinfo,tree)
	local offset=5
	tree:add(f_cnt1,buffer(offset,2))
	offset = offset + 2
	tree:add(f_cnt2,buffer(offset,1))
	offset = offset + 2
end