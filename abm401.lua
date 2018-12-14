-- ABM401


function axon_abm401_messagedatastyleA(tree, range)

    local f_empty = ProtoField.new("Parser Empty", "axon.empty", ftypes.BOOLEAN)

    local message = {}
    local message_data = axon_getValue(range)
    message.empty = bit32.extract(message_data,8)
    message.stale = bit32.extract(message_data,7)
    message.skipped = bit32.extract(message_data,6)
    message.bus = bit32.extract(message_data,1,5)
    message.parity = bit32.extract(message_data,0)
    message.sdi = bit32.extract(message_data,9,2)
    message.ssm = bit32.extract(message_data,30,2)
    message.data = bit32.extract(message_data,11,19)
    
    tree:add(range, string.format("Info Word. Empty: %x Stale: %x Skipped: %x Bus: %d", message.empty, message.stale, message.skipped, message.bus))
    tree:add(range, string.format("ARINC. SSM: %x SDI: %x Data: %#x", message.ssm, message.sdi, message.data))
    
    --local child, value = tree:add_packet_field(f_empty, tvb:range(0,3), ENC_UTF_8 + ENC_STRING)
    
end
