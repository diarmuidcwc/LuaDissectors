# LuaDissectors


Lua based Wireshark dissecgfors
(c) Diarmuid Collins dcollins@curtisswright.com



# Install

Clone this repo into a your Wireshark Configuation Profile directory (Edit -> Configuration Profile -> Blue Link) and call the folder "plugins"
Wireshark will pick up all the dissectors automatically

A number of protocols have heuristic checkers so that Wireshark will automatically check if a packet might be a specific format and will attempt to decom that packet.

If you want the dissectors to automatically run on particular ports, then you need to register that port with the dissector, eg port 5566 will receive inetx traffic
```lua
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle traffic on udp port 5566
udp_table:add(5566,inetx_generic_proto)
```

You can also dissect specific packets in Wireshark by right-clicking on a packet and selecting _Decode As_ -> INETX


# Creating your own dissectors

The included dissectors should give you a good idea on how to create custom dissectors. Generally you 
* Declare a new protocol using the Proto() syntax 
* Declare some new fields that are part of the protocol using ProtoField()
* Write the dissector function, populating those fields with the payload. Step through each payload byte/word etc and assign it to a field
