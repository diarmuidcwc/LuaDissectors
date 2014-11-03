LuaDissectors
=============

A bunch of lua dissectors for Wireshark that support iNet-X and IENA packet formats
(c) Diarmuid Collins dcollins@curtisswright.com


#Install

Clone this repo into a subdirectory of your Wireshark installation for instance _LuaDissectors_
Edit your init.lua adding the following lines below the existing dofile 

```lua
CUSTOM_DISSECTORS = DATA_DIR.."LuaDissectors"

dofile(CUSTOM_DISSECTORS.."\\inetx_generic.lua")
dofile(CUSTOM_DISSECTORS.."\\iena_generic.lua")
```

This will include both the iNet-X and IENA (TM) dissectors

# Creating your own dissectors

The included dissectors should give you a good idea on how to create custom dissectors. Generally you 
* Declare a new protocol using the Proto() syntax 
* Declare some new fields that are part of the protocol using ProtoField()
* Write the dissector function, populating those fields with the payload