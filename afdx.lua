
-------------------------------------------------------
-- This is a Wireshark dissector for the Airbus AFDX (TM) packet format
-- http://en.wikipedia.org/wiki/Avionics_Full-Duplex_Switched_Ethernet
-------------------------------------------------------

--  2014 Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuidcwc/LuaDissectors


afdx_proto = Proto("afdx","Generic AFDX Protocol")

-- Declare a few fields
f_vlink = ProtoField.uint8("afdx.vlink","Virtual Link",base.DEC)
f_interfaceid = ProtoField.uint8("afdx.interfaceid","Interface ID",base.HEX)
f_networkid = ProtoField.uint8("afdx.networkid","Network ID",base.HEX)
f_equipmentid = ProtoField.uint8("afdx.equipmentid","Equipmnt ID",base.HEX)
f_type = ProtoField.uint16("afdx.type","Type",base.HEX)

afdx_proto.fields = {f_vlink,f_interfaceid,f_networkid,f_equipmentid,f_type}


-- create a function to dissect it
function afdx_proto.dissector(buffer,pinfo,tree)
  local offset=0   -- constant field
  
  pinfo.cols.protocol = "afdx"
  local AFDX = tree:add(afdx_proto,buffer(offset,14),"AFDX ")
  
  -- create a sub tree with the ethernet src/dst mac fields
  local dst_mac = AFDX:add(afdx_proto,buffer(offset,6),"Dst MAC")
  offset = offset + 4   -- constant field

  dst_mac:add(f_vlink,buffer(offset,2))
  vlink = buffer(offset,2):uint()
  offset = offset + 2
  
  local src_mac = AFDX:add(afdx_proto,buffer(offset,6),"Src MAC")
  offset = offset + 3 -- skup constant f ield
  
  src_mac:add(f_networkid,buffer(offset,1))
  offset = offset + 1 
  
  src_mac:add(f_equipmentid,buffer(offset,1))
  offset = offset + 1 
  
  local ifid = (buffer(offset,1):uint())/32
  --src_mac:add(buffer(offset,1),"IFID="..ifid)
  src_mac:add(f_interfaceid,buffer(offset,1),ifid)
  offset = offset + 1
  
  -- Make the headline more informative
  AFDX:set_text("AFDX, Virtual Link: ".. vlink .. ", Interface ID:" .. ifid)
  
  AFDX:add(f_type,buffer(offset,2))
  offset = offset + 2 

  
    
end


-- The trailer
afdxseq = Proto("afdxseq","AFDX Trailer")
f_sequence = ProtoField.uint32("afdxseq.sequence","Sequence Number",base.DEC)
afdxseq.fields = {f_sequence}

function afdxseq.dissector(buffer,pinfo,tree)
  local offset=0   -- constant field
  local Trailer = tree:add(afdxseq,buffer(offset,1),"AFDX Trailer")
  Trailer:add(f_sequence,buffer(offset,1))
end

--afdx_table = DissectorTable.new("afdx.proto", "AFDX Protocol", FT_UINT16, BASE_DEC)
--afdx_seqtable = DissectorTable.new("afdxseq.proto", "AFDX Sequence", FT_UINT16, BASE_DEC)
--afdx_table:add(1,afdx_proto)
--afdx_table:add(1,afdxseq)

