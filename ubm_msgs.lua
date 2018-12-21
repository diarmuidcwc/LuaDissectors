
ubm401_proto = Proto("ubm401", "UBM401 Payload")

f_ubm_continuity = ProtoField.bool("ubm401.continuity", "Continuity", base.NONE)    
f_ubm_padding = ProtoField.uint8("ubm401.padding", "Padding", base.DEC)

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
        
  cont  = bit32.extract(hdr_word,12,1)
  pad  = bit32.extract(hdr_word,10,2)
        
  
  subtree:add(f_ubm_continuity,buffer(offset,2), cont)
  subtree:add(f_ubm_padding,buffer(offset,2), pad)
  offset = offset + 2
  subtree:add(buffer(offset, buf_len - pad - 2),"Data")
  offset = offset + buf_len - pad - 2
  if pad > 0 then
	 subtree:add(buffer(offset, pad),"Padding")
  end 

end
