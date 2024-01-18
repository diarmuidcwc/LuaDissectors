require("common")

----------------------------
-- ARINC429 message
----------------------------

-- declare our protocol
arinc429_generic_proto = Proto("a429", "MyARINC 429 Protocol")

-- Declare a few fields
f_a429_par = ProtoField.uint8("a429.parity",  "Parity", base.DEC)
f_a429_ssm = ProtoField.uint8("a429.ssm",     "SSM",    base.DEC)
f_a429_sdi = ProtoField.uint16("a429.sdi",    "SDI",    base.DEC)
f_a429_data = ProtoField.uint16("a429.data",  "Data",   base.HEX)
f_a429_label = ProtoField.uint16("a429.label","Label",  base.OCT)
arinc429_generic_proto.fields = {f_a429_par, f_a429_ssm, f_a429_sdi, f_a429_data, f_a429_label}

-- create a function to dissect it
function arinc429_generic_proto.dissector(buffer, pinfo ,ptree)
	offset = 0
	
	local parity = buffer(offset,1):uint() / 128
	local ssm = buffer(offset,1):uint()/32 % 4
	local data = ((buffer(offset,1):uint() % 32) * 256 + buffer(offset+1,1):uint() ) * 64 + (buffer(offset+2,1):uint() / 4)
	local sdi = buffer(offset+2,1):uint() % 4
	local label = reverse_byte_bit_order(buffer(offset+3,1):uint()+1)
	
	-- arinc_subtree:add(buffer(offset,4),  string.format(" Label: 0o%03o Par:%#01x SSM:%#01x Data:%#05x SDI:%#01x", label, parity, ssm, data, sdi))
	local tree = ptree:add(arinc429_generic_proto,buffer(),"ARINC-429 Word")
	tree:add(f_a429_label, buffer(offset,2), label)
	tree:add(f_a429_ssm, buffer(offset,2), ssm)
	tree:add(f_a429_sdi, buffer(offset,2), sdi)
	tree:add(f_a429_par, buffer(offset,2), parity)
	tree:add(f_a429_data, buffer(offset,2), data)
end
