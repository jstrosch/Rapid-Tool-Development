import re
from idautils import *
from idc import *

suspicious_api = ["IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess","OutputDebugString"]

detect_count = 0
timing_checks = []


def resetLineColors():

	heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))

	for i in heads:
		if GetMnem(i) == "call":
			SetColor(i, CIC_ITEM, 0xFFFFFFFF)

#### Begin #####

resetLineColors()

currentAddress = ScreenEA()

# Get the start and end address of .text section
text_start = SegStart(ScreenEA())
text_end = SegEnd(ScreenEA())

print "[*] Analysing text section 0x%08x to 0x%08x" % (text_start, text_end)

# Get all instructions for the function
heads = Heads(text_start,text_end)

#find suspiciuos API calls
for i in heads:
	instruction = GetMnem(i)

	# Check for basic Windows API calls
	if instruction == "call":

		call_target = GetOpnd(i, 0)
		call_address = GetOperandValue(i,0)

		if any(api_call in call_target for api_call in suspicious_api):
			print "[!] SUSPICIOUS: " + call_target + " at " + hex(i)
			SetColor(i, CIC_ITEM, 0xEE82EE)
			detect_count += 1

	# Check for access to PEB
	if instruction == "mov":

		source = GetOpnd(i,1)

		if re.match(r'.*fs:[?30h?]?',source, re.I):
			print "[!] SUSPICIOUS: Use of PEB at " + hex(i)

			SetColor(i, CIC_ITEM, 0xEE82EE)
			detect_count += 1

	# Check for INT3 scanning
	if instruction == "mov":

		source = GetOpnd(i,1)

		if source == "0CCh":
			print "[!] SUSPICIOUS: Possible INT3 Scanning at " + hex(i)
			SetColor(i,CIC_ITEM,0xEE82EE)
			detect_count += 1

	# Check for rdtsc timing

	if instruction == "rdtsc":
		timing_checks.append(i)


if len(timing_checks) >= 2:
	print "[!] Timing checks detected at the following locations: "

	for check in timing_checks:
		print "\t" + hex(check)
		SetColor(check,CIC_ITEM,0xEE82EE)


print "\n\n[!] DONE! Found %d suspicous function calls\n\n" % detect_count
