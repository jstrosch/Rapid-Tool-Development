import pefile, urllib, urllib2, urlparse, peutils, os, struct, sys, string, datetime, getopt, hashlib, mmap, exceptions, binascii

try:
    import simplejson
except ImportError:
    print 'You must install simplejson for VirusTotal, see http://www.undefined.org/python/'

#VirusTotal API Key
vtapi = ""

# suspicious APIs to alert on
alerts = ['Crypt', 'OpenProcess', 'VirtualAllocEx','WriteProcessMemory', 'CreateRemoteThread', 'ReadProcessMemory',
          'CreateProcess', 'WinExec', 'ShellExecute', 'HttpSendRequest', 'InternetReadFile', 'InternetConnect',
          'CreateService', 'StartService']


class VirusTotal:
    def __init__(self, file):
        self.file = file

        f = open(self.file, "rb")
        self.content = f.read()
        f.close()

    def check(self, res):
        url = "https://www.virustotal.com/api/get_file_report.json"
        parameters = {"resource": res,
                      "key": vtapi}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()
        response_dict = simplejson.loads(json)
        try:
            return response_dict.get("report")[1]
        except:
            return {}

    def upload_file(self):
        host = "www.virustotal.com"
        selector = "http://www.virustotal.com/api/scan_file.json"
        fields = [("key", vtapi)]
        file_to_send = self.content
        files = [("file", os.path.basename(self.file), file_to_send)]
        return post_multipart(host, selector, fields, files)

    def submit(self):
        resource = hashlib.md5(self.content).hexdigest()
        detects = self.check(resource)
        if len(detects) > 0:
            print 'File already exists on VirusTotal!'
            return detects
        print 'File does not exist on VirusTotal, uploading...'
        json = self.upload_file()
        if json.find("scan_id") != -1:
            offset = json.find("scan_id") + len("scan_id") + 4
            scan_id = json[offset:]
            scan_id = scan_id[:scan_id.find("\"")]
            print 'Trying scan_id %s for %d seconds' % (scan_id, MAXWAIT)
            i = 0
            while i<(MAXWAIT/10):
                detects = self.check(scan_id)
                if len(detects) > 0:
                    return detects
                time.sleep(MAXWAIT/10)
                i += 1
        return {}



def printSections(pe):
	sys.stdout.write("\tName\tVirtual Address\n")
	for section in pe.sections:
		sys.stdout.write("\t{:s}\t0x{:08x}\n".format(section.Name,section.VirtualAddress))

def printImports(pe):
	if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
		  print "\t" + entry.dll
		  for imp in entry.imports:
		  	alerttxt = "\t\t"
		  	for alert in alerts:
		  		if imp.name is not None and imp.name != "":
					if imp.name.startswith(alert):
				   		alerttxt = "[!Alert!]\t"
				   		break

			print '%s%s %s' % (alerttxt, hex(imp.address), imp.name)

	else:
		print "\tNo Imports Found"

def printExports(pe):
	if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
	  		print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
	else:
		print "\tNo Exports Found"

def matchSignatures(pe):
	peid = peutils.SignatureDatabase('peid_sigs/userdb.txt')

	matches = peid.match(pe, ep_only = True)

	if matches is None:
		print "\t[!] Nothing found, scanning more than ep..."
		matches = peid.match(pe, ep_only = False)

	print "[*] Found:"
	if matches is not None:
		if len(matches) == 1:
			print "\t" + str(matches)
		else:
			for match in matches:
				print "\t" + str(match[0]) + "\t" + str(match[1])
	else:
		print "\tNo Matches"


def usage():
	print "[!] Provide a file name"

def main(argv):

	file_name = ""

	try:
		opts, args = getopt.getopt(argv,'f:')
	except getopt.GetoptError:
		print usage
		sys.exit(2)

	if(len(opts) == 0):
		usage()
		sys.exit()

	for opt, arg in opts:
		if opt == "-f":
			file_name = arg
		else:
			usage()
			sys.exit()

	print "[*] Beginning analysis on " + file_name + "..."

	pe = pefile.PE(file_name)

	print "[*] Compiled:\t\t%s" % (datetime.datetime.fromtimestamp(
        							int(pe.FILE_HEADER.TimeDateStamp)).strftime('%Y-%m-%d %H:%M:%S'))
	print "[*] Magic Number:\t%x" % (pe.DOS_HEADER.e_magic)
	print "[*] Entry Point:\t%08x" % (pe.OPTIONAL_HEADER.AddressOfEntryPoint)
	print "[*] Sections:"
	printSections(pe)
	print "\n[*] Imports..."
	printImports(pe)
	print "\n[*] Exports..."
	printExports(pe)

	#PEiD
	print "\n\n[*] Matching for PEiD signatures..."
	matchSignatures(pe)

	#VirusTotal
	print "\n[*] Sending to VirusTotal..."
	if not sys.modules.has_key("simplejson"):
		print 'You must install simplejson'
		sys.exit()
	vt = VirusTotal(file_name)
	detects = vt.submit()
	for key,val in detects.items():
		print "\t\t%s => %s" % (key, val)
	print

	print "\n[*] Finished!\n\n"


if __name__ == '__main__':
	main(sys.argv[1:])