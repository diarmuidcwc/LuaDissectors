local bit32 = require("bit32_compat")

function getValue(buffer_range)
  return buffer_range: uint()
end


-- ARINC429 Parser Type A Word. This is used in the ABM parsers.

arinc429a_proto = Proto("arinc429typea", "Arinc 429 Style A")

f_arinca_ssm = ProtoField.uint8("arinc429typea.ssm", "SSM", base.DEC)    
f_arinca_data = ProtoField.uint8("arinc429typea.data", "Data", base.HEX)    
f_arinca_sdi = ProtoField.uint8("arinc429typea.sdi", "SDI", base.DEC)    
f_arinca_empty = ProtoField.bool("arinc429typea.empty", "Empty", base.NONE)    
f_arinca_stale = ProtoField.bool("arinc429typea.stale", "Stale", base.NONE)    
f_arinca_skipped = ProtoField.bool("arinc429typea.stale", "Skipped", base.NONE)    
f_arinca_bus = ProtoField.uint8("arinc429typea.bus", "Bus", base.DEC)    
f_arinca_slot = ProtoField.uint32("arinc429typea.slot","ARINC Slot",base.DEC)

arinc429a_proto.fields = {f_arinca_ssm, f_arinca_data, f_arinca_sdi, f_arinca_empty, f_arinca_stale, f_arinca_skipped, f_arinca_bus, f_arinca_slot}


function arinc429a_proto.dissector(buffer,pinfo,tree)

  pinfo.cols.protocol = "arinc429typea"
  
  local subtree = tree:add(buffer(0,4),"Arinc Type A Message")
  local offset=0
  
  local arinc_word = getValue(buffer(offset,4))
  local aw = {}
        
  aw.ssm  = bit32.extract(arinc_word,30,2)
  aw.data  = bit32.extract(arinc_word,11,19)
  aw.sdi  = bit32.extract(arinc_word,9,2)
  aw.empty  = bit32.extract(arinc_word,8)
  aw.stale  = bit32.extract(arinc_word,7)
  aw.skipped  = bit32.extract(arinc_word,6)
  aw.bus  = bit32.extract(arinc_word,1,5)
        
  subtree:add(f_arinca_ssm,buffer(offset,4), aw.ssm)
  subtree:add(f_arinca_data,buffer(offset,4), aw.data)
  subtree:add(f_arinca_sdi,buffer(offset,4), aw.sdi)
  subtree:add(f_arinca_empty,buffer(offset,4), aw.empty)
  subtree:add(f_arinca_stale,buffer(offset,4), aw.stale)
  subtree:add(f_arinca_skipped,buffer(offset,4), aw.skipped)
  subtree:add(f_arinca_bus,buffer(offset,4), aw.bus)
  
end

local ARINC_SSM= {
	[0x0]="Normal Operation",
	[0x1]="No Computed Data",
	[0x2]="Functional Test",
	[0x3]="Failure Warning",
}

-- ARINC429 Raw Word. This is an actual standard Arinc word. Used in the packetiuzer
arinc429_proto = Proto("arinc429", "Arinc 429 Word")
arincfields = arinc429_proto.fields

arincfields.ssm = ProtoField.uint8("arinc429.ssm", "Sign Status Matrix (SSM)", base.HEX, ARINC_SSM)    
arincfields.data = ProtoField.uint8("arinc429.data", "Data", base.HEX)    
arincfields.sdi = ProtoField.uint8("arinc429.sdi", "Source/Destination Identifier (SDI)", base.DEC)    
arincfields.label = ProtoField.uint8("arinc429.label", "Label", base.OCT)    
arincfields.par = ProtoField.uint8("arinc429.parity", "Parity", base.HEX)    


function arinc429_proto.dissector(buffer, pinfo, tree)

  --pinfo.cols.protocol = pinfo.cols.protocol .. " arinc429"
  local subtree
  local arinc_word
  local offset=0
  
  if tonumber(pinfo.private.arinc_le) == 1 then
	arinc_word = buffer(offset,4):le_uint()
	subtree = tree:add(buffer(0,4),"ARINC429 Word (little endian)")
  else
	arinc_word = buffer(offset,4):uint()
	subtree = tree:add(buffer(0,4),"ARINC429 Word (big endian)")
  end
   
  local aw = {}
        
  aw.ssm  = bit32.extract(arinc_word,29,2)
  aw.data  = bit32.extract(arinc_word,10,19)
  aw.sdi  = bit32.extract(arinc_word,8,2)
  aw.par  = bit32.extract(arinc_word,31,1)
  aw.label  = 0
  for bit_offset=0,7 do
    bit_value = bit32.extract(arinc_word,bit_offset,1)
    aw.label = aw.label + bit32.lshift(bit_value, 7-bit_offset)
  end
        
  subtree:add(arincfields.ssm,  buffer(offset,4), aw.ssm)
  subtree:add(arincfields.data, buffer(offset,4), aw.data)
  subtree:add(arincfields.sdi,  buffer(offset,4), aw.sdi)
  subtree:add(arincfields.par,  buffer(offset,4), aw.par)
  subtree:add(arincfields.label,buffer(offset,4), aw.label)
  
end
