local bit32 = require("bit32_compat")

function getValue(buffer_range)
  return buffer_range: uint()
end

cbm_proto = Proto("cbm", "CANBus")

local CBM_MSG_TYPE = {
	[0x0]="Standard ID",
	[0x1]="Extended ID",
}
f_cbm_msgtype = ProtoField.uint8("cbm.msgtype", "Message Type", base.HEX, CBM_MSG_TYPE)  

local CBM_FD = {
	[0x0]="CAN 2.0",
	[0x1]="CAN FD",
} 
--f_cbm_fd = ProtoField.uint8("cbm.fdf", "CAN Version", base.HEX, CBM_FD)  
local CBM_PAD = {
	[0x0]="No Padding",
	[0x1]="Padded",
} 
f_cbm_pad = ProtoField.uint8("cbm.pad", "Payload Padding", base.HEX, CBM_PAD)  
f_cbm_pb  = ProtoField.uint8("cbm.padbits", "Padded Bit Count", base.DEC)
    
f_cbm_sid = ProtoField.uint16("cbm.sid", "Identifier A", base.HEX)    
f_cbm_eid = ProtoField.uint32("cbm.eid", "Identifier B", base.HEX)
  
f_cbm_fdf = ProtoField.uint8("cbm.fdf", "CAN Version(FDF)", base.HEX, CBM_FD)  
f_cbm_brs = ProtoField.uint8("cbm.brs", "Bit Rate Switch(BRS)", base.HEX)  
f_cbm_srr = ProtoField.uint8("cbm.srr", "Substitute remote request(SRR)", base.HEX)  
f_cbm_ide = ProtoField.uint8("cbm.ide", "Identifier Extension Bit(IDE)", base.HEX)  
f_cbm_rtr = ProtoField.uint8("cbm.rtr", "Remote Transmission Request(RTR)", base.HEX)  
f_cbm_dlc = ProtoField.uint8("cbm.dlc", "Data Length Code(DLC)", base.DEC)  
local CBM_DLC_LOOKUP = {
	[0x0]=0,
	[0x1]=1,
	[0x2]=2,
	[0x3]=3,
	[0x4]=4,
	[0x5]=5,
	[0x6]=6,
	[0x7]=7,
	[0x8]=8,
	[0x9]=12,
	[0xA]=16,
	[0xB]=20,
	[0xC]=24,
	[0xD]=32,
	[0xE]=48,
	[0xF]=64,
} 


 
cbm_proto.fields = {f_cbm_msgtype, f_cbm_pad, f_cbm_pb, f_cbm_fdf, f_cbm_brs, f_cbm_sid, f_cbm_eid, f_cbm_srr, f_cbm_ide, f_cbm_rtr, f_cbm_dlc}

function cbm_proto.dissector(buffer,pinfo,tree)

  pinfo.cols.protocol = "cbm"
  
  local v_buf_len = buffer:len()
  local subtree = tree:add(buffer(0,v_buf_len),"CBM Parser Aligned Message")
  local offset=0
  
  local _word1 = getValue(buffer(offset,2))
  local _word2 = getValue(buffer(offset + 2,2))
  local _word4 = getValue(buffer(offset + 6,2))
  local cbmword = {}
        
  cbmword.mt  = bit32.extract(_word1,15,1)
--cbmword.fd  = bit32.extract(_word1,14,1)
  cbmword.pad  = bit32.extract(_word1,5,1)
  cbmword.pb  = bit32.extract(_word1,0,5)
  cbmword.fdf = bit32.extract(_word2,15,1)
  cbmword.srr  = bit32.extract(_word4,15,1)
  cbmword.ide  = bit32.extract(_word4,14,1)
  cbmword.rtr  = bit32.extract(_word4,13,1)
  cbmword.brs  = bit32.extract(_word4,12,1)
  cbmword.dlc  = bit32.extract(_word4,8,4)
  datalen = CBM_DLC_LOOKUP[cbmword.dlc]
        
  subtree:add(f_cbm_msgtype,buffer(offset,2), cbmword.mt)
  --subtree:add(f_cbm_fd,buffer(offset,2), cbmword.fd)
  subtree:add(f_cbm_pad,buffer(offset,2), cbmword.pad)
  subtree:add(f_cbm_pb,buffer(offset,2), cbmword.pb)
  
  offset= offset + 2
  
  subtree:add(f_cbm_fdf,buffer(offset,1), cbmword.fdf)
  subtree:add(f_cbm_sid,buffer(offset,2), bit32.extract(getValue(buffer(offset,2)),4,11))
  if cbmword.mt == 1 then
    subtree:add(f_cbm_eid,buffer(offset+1,3), bit32.extract(getValue(buffer(offset,4)),0,18))
  end
  offset= offset + 4 
  subtree:add(f_cbm_srr,buffer(offset,1), cbmword.srr)
  subtree:add(f_cbm_ide,buffer(offset,1), cbmword.ide)
  subtree:add(f_cbm_rtr,buffer(offset,1), cbmword.rtr)
  subtree:add(f_cbm_brs,buffer(offset,1), cbmword.brs)
  subtree:add(f_cbm_dlc,buffer(offset,1), cbmword.dlc)
  offset = offset + 1
  if cbmword.rtr == 0 and cbmword.dlc > 0 then
  subtree:add(buffer(offset,datalen),"Payload Length=".. datalen .." Bytes")
  end
end
