from idautils import *
from idc import *

function_count = 0
debug = True

def resetLineColors():
	global debug

	if debug:
		print "Seg start %08x to end %08x" % (SegStart(ScreenEA()), SegEnd(ScreenEA()))

	heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))

	for i in heads:
		if GetMnem(i) == "call":
			SetColor(i, CIC_ITEM, 0xFFFFFFFF)

def find_all_func_calls(call_instruction, tabs):
	global function_count, debug

	call_target = GetOpnd(call_instruction, 0)
	call_address = GetOperandValue(call_instruction,0)
	print "%s call at 0x%08x to %s (0x%08x)" % ((' ' * tabs), call_instruction,call_target, call_address)

	beginCalledFunc = GetFunctionAttr(call_address, FUNCATTR_START)
	endCalledFunc = PrevHead(GetFunctionAttr(call_address, FUNCATTR_END))

	if beginCalledFunc == BADADDR or endCalledFunc == BADADDR:
		return

	heads = Heads(beginCalledFunc, endCalledFunc)

	for i in heads:
		if GetMnem(i) == "call":
			SetColor(i, CIC_ITEM, 0xc7fdff)
			function_count += 1
			find_all_func_calls(i,(tabs+1))

#### Begin #####

resetLineColors()

currentAddress = ScreenEA()

# Get the start and end address of current function
beginFunc = GetFunctionAttr(currentAddress, FUNCATTR_START)
endFunc = PrevHead(GetFunctionAttr(currentAddress, FUNCATTR_END))

# Get all instructions for the function
heads = Heads(beginFunc,endFunc)

# Walk each instruction, if it is a call instruction highlight it
for instruction in heads:
	if GetMnem(instruction) == "call":
		SetColor(instruction, CIC_ITEM, 0xc7fdff)

# is current instruction a call? if so, recursively check for all function calls
if GetMnem(currentAddress) == "call":
	print "[!] You're on a call instruction, analysing..."

	find_all_func_calls(currentAddress,0)

print "\n\n[!] DONE! Found %d function calls\n\n" % function_count
