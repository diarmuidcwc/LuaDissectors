dofile(CUSTOM_DISSECTORS.."\\common.lua")
-- trivial protocol example
-- declare our protocol
proglink_proto = Proto("proglinkp","ProgLink Protocol")

function proglink_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "proglink"
  local prog_top_subtree = tree:add(proglink_proto,buffer(),"Proglink Protocol Data")
  local offset = 0
  if ( buffer(offset,2):uint() == 5 ) then
    -- poll command
    prog_top_subtree:append_text(" - Poll")
    prog_top_subtree:add(buffer(offset,2),"Poll Command" )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,2),"Command Sequence Number: ".. buffer(offset,2):uint() )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,2),"Status Match: ".. buffer(offset,2):uint() )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,2),"Status Mask: ".. buffer(offset,2):uint() )

  elseif ( buffer(offset,2):uint() == 0  ) then
    -- host id
    prog_top_subtree:append_text(" - Host Identifier")
    prog_top_subtree:add(buffer(offset,2),"Host Identifier" )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,2),"Sequence Number: ".. buffer(offset,2):uint() )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,2),"Don't care: ".. buffer(offset,2):uint() )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,2),"KAM UDP port: ".. buffer(offset,2):uint() )
    
  elseif ( buffer(offset,2):uint() == 1  ) then
    -- write
    prog_top_subtree:append_text(" - Write ")
    prog_top_subtree:add(buffer(offset,2),"Write Command" )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,2),"Sequence Number: ".. buffer(offset,2):uint() )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,1),"Don't care: ".. buffer(offset,1):uint() )
    offset = offset + 1
    prog_top_subtree:add(buffer(offset,1),"Size ".. buffer(offset,1):uint() )
    local size =  buffer(offset,1):uint()
    offset = offset + 1
    local word_pair_count = 0
    repeat
      datatree = prog_top_subtree:add(buffer(offset,4),"Word Pair: " .. word_pair_count)
      datatree:add(buffer(offset,4),"Payload: ".. tostring(buffer(offset,4)) )
      word_pair_count = word_pair_count + 1
      offset = offset + 4
    until (word_pair_count == size)
    
  elseif ( buffer(offset,2):uint() == 2  ) then
    -- Read 
    prog_top_subtree:append_text(" - Read ")
    prog_top_subtree:add(buffer(offset,2),"Read Command" )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,2),"Sequence Number: ".. buffer(offset,2):uint() )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,1),"Don't care: ".. buffer(offset,1):uint() )
    offset = offset + 1
    prog_top_subtree:add(buffer(offset,1),"Size ".. buffer(offset,1):uint() )
    local size =  buffer(offset,1):uint()
    offset = offset + 1
    local word_pair_count = 0
    -- repeat
      -- datatree = prog_top_subtree:add(buffer(offset,4),"Word Pair: " .. word_pair_count)
      -- datatree:add(buffer(offset,4),"Payload: ".. tostring(buffer(offset,4)) )
      -- word_pair_count = word_pair_count + 1
      -- offset = offset + 4
    -- until (word_pair_count == size)
    
  elseif ( buffer(offset,2):uint() == 3  ) then
    -- Read Resp
    prog_top_subtree:append_text(" - Read Response")
    prog_top_subtree:add(buffer(offset,2),"Read Response Command" )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,2),"Sequence Number: ".. buffer(offset,2):uint() )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,1),"Don't care: ".. buffer(offset,1):uint() )
    offset = offset + 1
    prog_top_subtree:add(buffer(offset,1),"Size ".. buffer(offset,1):uint() )
    local size =  buffer(offset,1):uint()
    offset = offset + 1
    local word_pair_count = 0
    repeat
      datatree = prog_top_subtree:add(buffer(offset,4),"Word Pair: " .. word_pair_count)
      datatree:add(buffer(offset,4),"Payload: ".. tostring(buffer(offset,4)) )
      word_pair_count = word_pair_count + 1
      offset = offset + 4
    until (word_pair_count == size)
     
  elseif ( buffer(offset,2):uint() == 4  ) then
    -- Command ack
    prog_top_subtree:append_text(" - Command Ack")
    prog_top_subtree:add(buffer(offset,2),"Command Ack" )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,2),"Sequence Number: ".. buffer(offset,2):uint() )
    
  elseif ( buffer(offset,2):uint() == 65535  ) then
    -- Command ack
    prog_top_subtree:append_text(" - Command Sequence Error")
    prog_top_subtree:add(buffer(offset,2),"Command Sequence Error" )
    offset = offset + 2
    prog_top_subtree:add(buffer(offset,2),"Sequence Number: ".. buffer(offset,2):uint() )    
  else
      prog_top_subtree:append_text(" - Unknown")
      
  end
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(4867,proglink_proto)
udp_table:add(2496,proglink_proto)
udp_table:add(1858,proglink_proto)

