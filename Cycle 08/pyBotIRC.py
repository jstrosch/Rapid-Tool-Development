import socket, urllib, urllib2, urlparse, os, struct, sys, string, datetime, getopt, hashlib, mmap, exceptions, binascii

try:
    import simplejson
except ImportError:
    print 'You must install simplejson for VirusTotal, see http://www.undefined.org/python/'

#VirusTotal API Key
vtapi = ""

#IRC Configuration
server = "irc.freenode.net"
channel = "#csc842"
botnick = "PyBotCSC842"

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

def send_message_irc(message):

	ircsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ircsock.connect((server, 6667)) # Here we connect to the server using port 6667

	#Debug
	#print ircsock.recv(10000)

	ircsock.send("USER "+ botnick +" "+ botnick +" "+ botnick +" :Python IRC Bot\n") # user authentication
	ircsock.send("NICK "+ botnick +"\n") # here we actually assign the nick to the bot

	ircsock.send("JOIN " + channel +"\n")

	while 1:
		ircmsg= ircsock.recv(2014)
		ircmsg = ircmsg.strip("\r\n")
		#print(ircmsg)

		# This keeps us connected
		if ircmsg.find("PING :") != -1:
			ircsock.send("PONG :Pong\n")

		# This is just for initialization, should come after MOTD
		# Means we are connected and can send messages to the channel
		if ircmsg.find("End of /NAMES") != -1:
			ircsock.send("PRIVMSG " + channel + " :" + message + "\n")
			break

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

	irc_message = "[*] Beginning analysis on " + file_name + "..."


	vt = VirusTotal(file_name)
	detects = vt.submit()

	if len(detects) > 0:
		irc_message += "[VirusTotal] Results..." + str(len(detects))
		num_detects = 0


		for key,val in detects.items():
			irc_message += "\t\t%s => %s" % (key, val)

			if num_detects > 4:
				break

			num_detects = num_detects + 1

	else:
		irc_message += "[VirusTotal] No Results"

	#Update on IRC
	send_message_irc(irc_message)


if __name__ == '__main__':
	main(sys.argv[1:])