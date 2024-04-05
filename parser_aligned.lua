
--dofile(CUSTOM_DISSECTORS.."\\parse_arinc.lua")

-- Parser Aligned Block

parser_block_proto = Proto("parserblock","Parser Block")
-- Declare a few fields that we are in
f_error = ProtoField.bool("parserblock.error","Error",base.NONE)
f_errorcode = ProtoField.uint8("parserblock.errorcode","Error Code",base.HEX)
f_quadbytes = ProtoField.uint32("parserblock.quadbytes","Quad Bytes",base.DEC)
f_messagecount = ProtoField.uint32("parserblock.count","Message Count",base.DEC)
f_busid = ProtoField.uint32("parserblock.busid","Bus ID",base.HEX)
f_elapsed = ProtoField.uint64("parserblock.elapsed","Elapsed Time",base.DEC)

parser_block_proto.fields = {f_error,f_errorcode,f_quadbytes,f_messagecount,f_busid,f_elapsed}
parser_block_proto.prefs["messagedissector"] = Pref.string("Message Dissector","arinc429","What dissector to use for the message data (can be arinc429, cbm, etc)")

-- create a function to dissect it
function parser_block_proto.dissector(buffer,pinfo,tree)

	pinfo.cols.protocol = "parserblock"
        
    offset = 0
    local error_bit = (buffer(offset,1):uint())/16
    local error_code = (buffer(offset,1):uint()/2) % 64   -- code = bits(6:1)
    local quad_bytes = (buffer(offset,2):uint()) % 256
    tree:add(f_error, buffer(offset,1), error_bit)
    if error_bit ~= 0 or error_code ~= 0 then
        -- generally error codes are not used, but display it if it is in use or non-zero
        -- (further interpretation is protocol specific)
        tree:add(f_errorcode, buffer(offset,1), error_code)
    end
    tree:add(f_quadbytes, buffer(offset,2), quad_bytes)
    offset = offset + 2
    tree:add(f_messagecount, buffer(offset,1), buffer(offset,1):uint())
    offset = offset + 1
    tree:add(f_busid, buffer(offset,1), buffer(offset,1):uint())
    offset = offset + 1
    tree:add(f_elapsed, buffer(offset,4), buffer(offset,4):uint64())
    offset = offset + 4
    local payload_len = (quad_bytes-2)*4
	if payload_len > 0 then
		--messagetree = tree:add(buffer(offset,payload_len),"Message" )	
		messagedissector = Dissector.get(parser_block_proto.prefs["messagedissector"])
		if parser_block_proto.prefs["messagedissector"] == "milstd1553" then
			tree:add(buffer(offset,1), "Transaction ID=" .. buffer(offset,1):uint())
			offset = offset + 1
			tree:add(buffer(offset,1), "Padding=" .. buffer(offset,1):uint())
			if buffer(offset,1):uint() == 0 then
				payload_len = payload_len - 2
			else
				payload_len = payload_len - 4
			end
			offset = offset + 1
		end
		subtree = tree:add(buffer(offset, payload_len),"Transaction")
		messagedissector:call(buffer(offset,payload_len):tvb(), pinfo, subtree)		
	end
	
end

-- Parser Aligned Payload
parser_payload_proto = Proto("parseraligned","Parser Aligned Payload")
f_elapsederror = ProtoField.uint32("parseraligned.elapsederrpr","Elapsed Error",base.DEC)

parser_payload_proto.fields = {f_elapsederror}

function parser_payload_proto.dissector(buffer,pinfo,tree)

    local payload_len = buffer:len()
    local offset = 0 
    local block = 1
    local quad_bytes = (buffer(offset,2):uint()) % 256
    local prev_elap = 0
	if quad_bytes ~= 0 then
		repeat
			local quad_bytes = (buffer(offset,2):uint()) % 256
			if quad_bytes == 0 or quad_bytes*4 > payload_len then
				subtree = tree:add(buffer(offset),"Illegal Block ".. block)
				subtree:add(buffer(offset,2 ),"Illegal Quad Bytes = ".. quad_bytes)
				subtree:add_expert_info(PI_PROTOCOL,PI_ERROR)
				payload_len = offset
			else
				local block_len = quad_bytes*4
				local elapsed = (buffer(offset+4,4):uint64())
				subtree = tree:add(buffer(offset,block_len),"Block ".. block)
				-- Check the elapsed time going backwards
				
				
				if elapsed < prev_elap then
					tree:add(f_elapsederror, buffer(offset+4,4), 1)
					subtree:add_expert_info(PI_PROTOCOL,PI_WARN)
				--else
				--    tree:add(f_elapsederror, buffer(offset+4,4), 0)
				end
				prev_elap = elapsed
				
				blockdissector = Dissector.get("parserblock")
				blockdissector:call(buffer(offset,block_len):tvb(),pinfo,subtree)
				offset = offset + block_len
				block = block + 1
			end
		until (offset == payload_len)
	end
end