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


-- ARINC429 Raw Word. This is an actual standard Arinc word. Used in the packetiuzer
arinc429_proto = Proto("arinc429", "Arinc 429 Word")

f_arinc_ssm = ProtoField.uint8("arinc429.ssm", "SSM", base.DEC)    
f_arinc_data = ProtoField.uint8("arinc429.data", "Data", base.HEX)    
f_arinc_sdi = ProtoField.uint8("arinc429.sdi", "SDI", base.DEC)    
f_arinc_label = ProtoField.uint8("arinc429.label", "Label", base.OCT)    
f_arinc_par = ProtoField.uint8("arinc429.parity", "Parity", base.DEC)    

arinc429a_proto.fields = {f_arinc_ssm, f_arinc_data, f_arinc_sdi, f_arinc_label, f_arinc_par}

function arinc429_proto.dissector(buffer,pinfo,tree)

  pinfo.cols.protocol = "arinc429"
  
  local subtree = tree:add(buffer(0,4),"Arinc Word")
  local offset=0
  
  local arinc_word = getValue(buffer(offset,4))
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
        
  subtree:add(f_arinc_ssm,buffer(offset,4), aw.ssm)
  subtree:add(f_arinc_data,buffer(offset,4), aw.data)
  subtree:add(f_arinc_sdi,buffer(offset,4), aw.sdi)
  subtree:add(f_arinc_par,buffer(offset,4), aw.par)
  subtree:add(f_arinc_label,buffer(offset,4), aw.label)
  
end
