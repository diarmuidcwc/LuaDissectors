-- 
-- This dissects the output parameters from the MAT/101

mat101_proto = Proto("mat101","Mat 101 Test")
-- Declare a few fields that we are in
f_result0= ProtoField.uint16("mat101.result0","Result0",base.HEX)
f_result1= ProtoField.uint16("mat101.result1","Result1",base.HEX)
f_result2= ProtoField.uint16("mat101.result2","Result2",base.HEX)
f_result3= ProtoField.uint16("mat101.result3","Result3",base.HEX)
f_result4= ProtoField.uint16("mat101.result4","Result4",base.HEX)
f_result5= ProtoField.uint16("mat101.result5","Result5",base.HEX)
f_result6= ProtoField.uint16("mat101.result6","Result6",base.HEX)
f_result7= ProtoField.uint16("mat101.result7","Result7",base.HEX)
f_result8= ProtoField.uint16("mat101.result8","Result8",base.HEX)
f_result9= ProtoField.uint16("mat101.result9","Result9",base.HEX)
f_result10= ProtoField.uint16("mat101.result10","Result10",base.HEX)
f_result11= ProtoField.uint16("mat101.result11","Result11",base.HEX)
f_result12= ProtoField.uint16("mat101.result12","Result12",base.HEX)
f_result13= ProtoField.uint16("mat101.result13","Result13",base.HEX)
f_result14= ProtoField.uint16("mat101.result14","Result14",base.HEX)
f_result15= ProtoField.uint16("mat101.result15","Result15",base.HEX)
f_mat_err_cnt= ProtoField.uint16("mat101.errcnt","Error count",base.DEC)
f_mat_time= ProtoField.string("mat101.time","Time")
f_mat_report= ProtoField.uint16("mat101.report","Report Reg",base.HEX)
f_mat_dsicount= ProtoField.uint16("mat101.dsicount","DSI Count",base.DEC)


mat101_proto.fields = {f_result0,f_result1,f_result2,f_result3,f_result4,f_result5,f_result6,f_result7,f_result8,f_result9,f_result10,f_result11,f_result12,f_result13,f_result14,f_result15,f_mat_err_cnt,f_mat_time,f_mat_report,f_mat_dsicount}

-- create a function to dissect it
function mat101_proto.dissector(buffer,pinfo,tree)

	pinfo.cols.protocol = "mat101"
	
	offset = 0
	
	tree:add(f_result0, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result1, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result2, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result3, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result4, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result5, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result6, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result7, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result8, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result9, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result10, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result11, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result12, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result13, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result14, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_result15, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_mat_err_cnt, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	local sbi_time = tostring(buffer(offset,6))
	local usec = string.sub(sbi_time,-6)
	local wall_time = sbi_to_walltime(sbi_time)
	--tree:add(buffer(offset,6),"BCU_Time (ptp equivalent): " .. os.date("!%H:%M:%S",wall_time+35))
	tree:add(buffer(offset,6), os.date("!%H:%M:%S",wall_time+35))
	offset = offset + 6
	
	tree:add(f_mat_report, buffer(offset,2), buffer(offset,2):uint())
	offset = offset + 2
	
	tree:add(f_mat_dsicount, buffer(offset,2), buffer(offset,2):uint())


end