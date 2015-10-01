## PyMal - Python Malware Scanner

The purpose of this script is to scan PE files for indications of malicious activity.  This script will display information about the file such as compile time and magic number.  It will also display imports and exports, marking any suspicious function calls based on a script-defined list.  PEiD signatures have been included and the file scanned against those signatures.  It will do an ep only scan then, if no results, try a deep scan.  Finally, the script will submit the file to VirusTotal and print the results.

# Dependencies

This script depends on [PE File](https://github.com/erocarrera/pefile) and [SimpleJSON](http://undefined.org/python)

# Usage

```
To scan a file:
$ python pyMal.py -f <file to scan>
```