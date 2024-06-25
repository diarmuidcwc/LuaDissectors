
ubm401_proto = Proto("ubm401", "UBM401 Payload")

local UBM401_CONTINUITY = {
	[0x0]="Complete Message",
	[0x1]="Last Fragment",
	[0x2]="First Fragment",
	[0x3]="Middle Fragment",
}

f_ubm_continuity = ProtoField.uint16("ubm401.continuity", "Continuity", base.HEX, UBM401_CONTINUITY, 0x3000)    
f_ubm_padding = ProtoField.uint16("ubm401.padding", "Padding", base.DEC, nil, 0xC00)

ubm401_proto.fields = {f_ubm_continuity, f_ubm_padding}

function getValue(buffer_range)
  return buffer_range: uint()
end

function ubm401_proto.dissector(buffer,pinfo,tree)

  pinfo.cols.protocol = "ubm401"
  
  local buf_len = buffer:len()
  
  local subtree = tree:add(buffer(0,buf_len),"Serial Message")
  local offset=0

   local hdr_word = getValue(buffer(offset,2))
        
  pad  = bit32.extract(hdr_word,10,2)
        
  
  subtree:add(f_ubm_continuity,buffer(offset,2))
  subtree:add(f_ubm_padding,buffer(offset,2))
  offset = offset + 2
  subtree:add(buffer(offset, buf_len - pad - 2),"Data")
  offset = offset + buf_len - pad - 2
  if pad > 0 then
	 subtree:add(buffer(offset, pad),"Padding")
  end 

end
