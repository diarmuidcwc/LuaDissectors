-------------------------------------------------------
-- This is a Wireshark dissector for the iNET packet format
-- http://www.irig106.org/docs/106-17/Chapter24.pdf
-------------------------------------------------------

-- Diarmuid Collins dcollins@curtisswright.com
-- https://github.com/diarmuidcwc/LuaDissectors

INET_PORT = 6678

inetpackage_protocol =  Proto("inetpkg", "INET Package")
f_inetpkgflags = ProtoField.uint16("inetpkg.flags","PackageFlags",base.HEX)
f_inetpkgdefinitionID = ProtoField.uint32("inetpkg.definition","Package Definition ID",base.DEC)
f_inetpkglen = ProtoField.uint16("inetpkg.length","Length",base.DEC)
f_inetpkgtime = ProtoField.uint32("inetpkg.timedelta","Time Delta",base.DEC)

inetpackage_protocol.fields = {f_inetpkgflags, f_inetpkgdefinitionID, f_inetpkglen, f_inetpkgtime}

    
function inetpackage_protocol.dissector(buffer, pinfo, tree)

    
    local offset = 0
	local v_buf_len = buffer:len()
    tree:add(f_inetpkgdefinitionID,buffer(offset,4))
    offset = offset + 4   
    tree:add(f_inetpkglen,buffer(offset,2))
    local v_len = buffer(offset,2):uint()
	offset = offset + 3
    tree:add(f_inetpkgflags,buffer(offset,1))
    offset = offset + 1  
    tree:add(f_inetpkgtime,buffer(offset,4))
    offset = offset + 4  
    tree:add(buffer(offset, v_len-12), "Data")    

end


inet_protocol =  Proto("inet", "INET")
f_inetflags = ProtoField.uint16("inet.flags","Flags",base.HEX)
f_inettype = ProtoField.uint8("inet.type","Message Type",base.DEC)
f_inetoptwc = ProtoField.uint8("inet.optwc","Option Word Count",base.DEC)
f_inetversion = ProtoField.uint8("inet.version","Version",base.DEC)
f_inetdefinitionID = ProtoField.uint32("inet.definition","Definition ID",base.HEX)
f_inetsequence = ProtoField.uint32("inet.sequence","Sequence",base.DEC)
f_inetlen = ProtoField.uint32("inet.length","Length",base.DEC)
f_inettimestamp = ProtoField.uint64("inet.timestamp","Timestamp",base.DEC)


inet_protocol.fields = {f_inetflags, f_inettype, f_inetoptwc, f_inetversion, f_inetdefinitionID, f_inetsequence, f_inetlen, f_inettimestamp}
    
function inet_protocol.dissector(buffer,pinfo,mtree)

    inetpackage_protocol = Dissector.get("inetpkg")
    
    pinfo.cols.protocol = "INET" -- the name in the wirshark view
    local offset=0
    local v_opt_word_count = buffer(0,1):uint() % 16
    local v_hdr_len = 24 + v_opt_word_count*4
    
    local inettree = mtree:add(inet_protocol,buffer(),"INET Protocol")
    local tree = inettree:add(inet_protocol, buffer(offset, v_hdr_len),"INET Header")
    
    local offset=0
    local v_version = buffer(offset,1):uint() /  16
    tree:add(f_inetoptwc,buffer(offset,1), v_opt_word_count)
    tree:add(f_inetversion,buffer(offset,1), v_version)
    offset = offset + 1
    tree:add(f_inettype,buffer(offset,1))
    offset = offset + 1
    tree:add(f_inetflags,buffer(offset,2))
    offset = offset + 2
    tree:add(f_inetdefinitionID,buffer(offset,4))
    offset = offset + 4
    tree:add(f_inetsequence,buffer(offset,4))
    offset = offset + 4
    tree:add(f_inetlen,buffer(offset,4))
    local v_inet_len = buffer(offset,4):uint()
    offset = offset + 4
    tree:add(f_inettimestamp,buffer(offset,8))
    offset = offset + 8
    
    local v_opt_count = 0
    if v_opt_word_count > 0 then
        repeat 
            tree:add(buffer(offset,4), "Application Word: " .. buffer(offset,4))
            offset = offset + 4
            v_opt_count = v_opt_count + 1
        until v_opt_count == v_opt_word_count
    end
    
    
    local v_pkg_len = buffer(offset+4,2):uint()
    
	local payload_tree = inettree:add(inet_protocol,buffer(v_hdr_len),"INET Payload")
	 
    local v_pkg_count = 0
    if v_pkg_len > 0 then
        repeat 
			local v_pkg_len = buffer(offset+4,2):uint()
            local pkg_tree = payload_tree:add(buffer(offset, v_pkg_len),"Package #" .. v_pkg_count)
            inetpackage_protocol:call(buffer(offset, v_pkg_len):tvb(), pinfo, pkg_tree)
            offset = offset + v_pkg_len
			if v_pkg_len % 4 ~= 0 then
				pad_len =  4 - (v_pkg_len % 4)
				pkg_tree:add(buffer(offset, pad_len), "Padding")
				offset = offset + pad_len
			end
            v_pkg_count = v_pkg_count + 1
        until offset == v_inet_len
    else
        local pkg_tree = payload_tree:add(buffer(offset, v_pkg_len),"Illegal length " .. v_pkg_len)
    end
end




-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register some ports
udp_table:add(INET_PORT, inet_protocol)
