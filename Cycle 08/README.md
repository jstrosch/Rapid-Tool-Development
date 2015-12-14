## pyBotIRC - Malware Analysis with IRC Integration

This is a python script that builds off some of the basic malware analysis work from previous cycles, it includes a component to send scan information to an IRC channel.

Overall, the script only submits the file to VirusTotal.  Once submission results are obtained, the script logs the resulting information to the configured IRC channel.  All configurable options are available at the top of the script.

# Requirements

This script is dependent on simpleJson for submission to VirusTotal

# Demo

A demo of this script is available on YouTube:

[YouTube Demo](https://youtu.be/8cYKfD-d9EY)

# Usage

Execute the Python script from the command line include the name of the file you want to scan

`
	$ python pyBotIRC.py -f some_file
`