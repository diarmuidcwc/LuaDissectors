LuaDissectors
=============

A bunch of lua dissectors for Wireshark that support iNet-X and IENA packet formats

(c) Diarmuid Collins dcollins@curtisswright.com


#Install

Clone this repo into a subdirectory of your Wireshark installation for instance _LuaDissectors_.

Edit your init.lua adding the following lines below the existing dofile 

```lua
CUSTOM_DISSECTORS = DATA_DIR.."LuaDissectors"

dofile(CUSTOM_DISSECTORS.."\\inetx_generic.lua")
dofile(CUSTOM_DISSECTORS.."\\iena_generic.lua")
```

This will include both the iNet-X and IENA (TM) dissectors

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