-- MIL-STD-1553 message dissector

local MIL_RX = {[0]="Receive", [1]="Transmit"}

milstd1553_proto = Proto("milstd1553", "MIL-STD-1553")

f_1553_cmd = ProtoField.uint16("milstd1553.command", "Command", base.HEX)    
f_1553_cmd2 = ProtoField.uint16("milstd1553.command2", "Command2", base.HEX)    
f_1553_address = ProtoField.uint16("milstd1553.address", "RT Address", base.HEX, nil, 0xF800)    
f_1553_rx = ProtoField.uint16("milstd1553.rx", "RX", base.HEX, MIL_RX, 0x400 )    
f_1553_subaddress = ProtoField.uint16("milstd1553.subaddress", "SubAddress", base.HEX, nil, 0x3E0)    
f_1553_num_words = ProtoField.uint16("milstd1553.words", "Number of Words", base.DEC, nil, 0x1F)    
f_1553_mode_code = ProtoField.uint16("milstd1553.words", "Mode Code", base.HEX, nil, 0x1F)    
f_1553_sts1 = ProtoField.uint16("milstd1553.sts1", "Status Word1", base.HEX)    
f_1553_sts2 = ProtoField.uint16("milstd1553.sts2", "Status Word2", base.HEX)    
milstd1553_proto.fields = {f_1553_cmd, f_1553_address, f_1553_rx, f_1553_subaddress, f_1553_num_words, f_1553_sts1, f_1553_sts2, f_1553_cmd2, f_1553_mode_code }

function milstd1553_proto.dissector(buffer, pinfo, tree, isRT2RT)
  local offset = 0
  local data_payload_len_words = 0
  local v_process_sts1_after_data = 0
  local v_command    = buffer(offset, 2):uint()

  local v_rt  = bit32.extract(v_command,11,5)  
  local v_is_tx  = bit32.extract(v_command,10,1) 
  local v_sa_or_mc  = bit32.extract(v_command,5,5)  
  local v_modecode_or_wordcount  = bit32.extract(v_command,0,5)
  
  -- Add the fields
  local comand_tree = tree:add(f_1553_cmd,buffer(offset, 2), v_command)
  tree:add(f_1553_address,buffer(offset, 2), v_command)
  tree:add(f_1553_rx,buffer(offset, 2), v_command)
  tree:add(f_1553_subaddress,buffer(offset, 2), v_command)
  offset = offset + 2
  
   
  local v_length_after_cmd1 =  buffer:len() - 2;
  
  if not (v_rt == 31) then
	-- non-broadcast
	  if ( v_sa_or_mc == 0 or v_sa_or_mc == 31) then
		-- Mode Code	
		tree:add(f_1553_mode_code, v_command)
		if (v_length_after_cmd1==0) then
			-- Error situation, report?
			tree:add(buffer(0, 2), string.format("Mode Code bits set in command for individual RT, but there are nothing else in the buffer!"))
			tree:add_expert_info(PI_CHECKSUM,PI_WARN)			
		elseif (v_length_after_cmd1==2) then
			-- M_S
			comand_tree:append_text( " (M_S)" )		
			-- expecting status word only 
			tree:add(f_1553_sts1, buffer(offset,2))
			offset = offset + 2
		elseif (v_length_after_cmd1==4) then 
		    -- M_SD
			comand_tree:append_text( " (M_SD)" )		
			-- expecting status word AND single data word (and there will be a padding of 2 bytes)
			tree:add(f_1553_sts1, buffer(offset,2))
			offset = offset + 2
			data_payload_len_words = 1
		else
			-- Error situation, report?
			tree:add(buffer(offset, v_length_after_cmd1), string.format("Mode Code bits set in command for individual RT, but there are unexpected long buffer after cmd1 with length of %d bytes, do not understand how to interpret it!", v_length_after_cmd1))
			tree:add_expert_info(PI_CHECKSUM,PI_WARN)			
		end
	  else
	    -- not Mode Code 
		 tree:add(f_1553_num_words, buffer(offset,2), v_command)
		 if (v_modecode_or_wordcount == 0) then
			data_payload_len_words = 32
		 else
			data_payload_len_words = v_modecode_or_wordcount
		 end
		 
		 if ( isRT2RT ) then
			comand_tree:append_text( " (RT2RT)" )		
			
			tree:add(f_1553_cmd2, buffer(offset,2))
			offset = offset + 2
			tree:add(f_1553_sts2, buffer(offset,2))
			offset = offset + 2
			
			-- then data, then status
			v_process_sts1_after_data = 1
		 else
			if (v_is_tx) then
			-- BC2RT, 
				comand_tree:append_text( " (BC2RT)" )		
			-- expect some data, then status
				v_process_sts1_after_data = 1				
			else
			-- RT2BC 
				comand_tree:append_text( " (RT2BC)" )		
			-- expect status
				tree:add(f_1553_sts1, buffer(offset,2))
				offset = offset + 2
				
			-- expect some data			
			end
		 end		 		 
	  end
  else
	-- broadcast
	  if ( v_sa_or_mc == 0 or v_sa_or_mc == 31) then
		-- Mode Code	
		tree:add(f_1553_mode_code, v_command)
		
		if (v_length_after_cmd1==0) then
			comand_tree:append_text( " (M)" )		
		elseif (v_length_after_cmd1==2) then
			comand_tree:append_text( " (MD)" )		
			data_payload_len_words = 1
		else
			tree:add(buffer(offset, v_length_after_cmd1), string.format("Mode Code bits set in command for broadcast, but there are unexpected long buffer after cmd1 with length of %d bytes, do not understand how to interpret it!", v_length_after_cmd1))
			tree:add_expert_info(PI_CHECKSUM,PI_WARN)			
		end
		
	  else
	    -- not Mode Code 
		tree:add(f_1553_num_words, v_command)
		if (v_modecode_or_wordcount == 0) then
			data_payload_len_words = 32
		else
			data_payload_len_words = v_modecode_or_wordcount
		end
		
		if (isRT2RT) then
			-- RT2RTs
			comand_tree:append_text( " (RT2RTs)" )		
			
			tree:add(f_1553_cmd2, buffer(offset,2))
			offset = offset + 2
			tree:add(f_1553_sts2, buffer(offset,2))
			offset = offset + 2
			-- no status expected as it is a broadcast
		else
			-- BC2RTs
			comand_tree:append_text( " (BC2RTs)" )		
			-- expect some data, 
			-- mistakes in NPD fig40?? we should not have any status there, as it is proadcast
			-- v_process_sts1_after_data = 1							
		end		
	  end
  end
    
  if data_payload_len_words > 0 then
	local data_subtree = tree:add(buffer(offset), "Data")
	for doffset = offset, offset+(2*(data_payload_len_words-1)), 2
	do
		--data_subtree:add(buffer(), string.format("doff=%d offset=%d", doffset, offset))
		data_subtree:add(buffer(doffset,2), string.format("%#06X", buffer(doffset,2):uint()))
	end
	offset = offset+2*(data_payload_len_words)
  end
  
  if not (v_process_sts1_after_data == 0) then 
	tree:add(f_1553_sts1, buffer(offset,2))
	offset = offset + 2 
  end  
end

-------------- iNETX wrapper

milstd1553_inetx_proto = Proto("milstd1553inetx", "MIL-STD-1553 in iNetX")
f_1553_transid = ProtoField.uint8("milstd1553inetx.transid", "Transaction ID", base.DEC) 
milstd1553_inetx_proto.fields = {f_1553_transid}

function milstd1553_inetx_proto.dissector(buffer,pinfo,tree)

  pinfo.cols.protocol = "milstd1553"
  
  local transaction_id = { 
  [0x0] = "BC -> RT", 
  [0x1] = "RT -> BC",
  [0x2] = "RT -> RT", 
  [0x3] = "M -> S", 
  [0x4] = "MD -> S", 
  [0x5] = "M -> SD", 
  [0x6] = "BC -> RTS", 
  [0x7] = "RT -> RTS", 
  [0x8] = "M", 
  [0x9] = "MD",
  [0x10] = "BC -> RT", 
  [0x11] = "RT -> BC", 
  [0x12] = "RT -> RT", 
  [0x13] = "M -> S", 
  [0x14] = "MD -> S", 
  [0x15] = "M -> SD",  
  [0x16] = "RT -> RTS"
  }
  
  local subtree = tree:add(buffer(),"Transaction")
  local offset=0
        
  subtree:add(f_1553_transid, buffer(offset,1))
  local v_id = buffer(offset,1):uint()
  local v_padding = buffer(offset+1,1):uint() / 128
  local v_length =  buffer:len() - 2 * v_padding - 2
  offset = offset + 2
  subtree:add(buffer(offset, v_length),"Transaction: " .. transaction_id[v_id])
  if v_id > 5 and v_id < 0xA then
	subtree:add(buffer(offset, v_length),"Broadcast " )
  end
  msgdissector = Dissector.get("milstd1553")
  msgdissector:call(buffer(offset):tvb(),pinfo,subtree)

  
end


