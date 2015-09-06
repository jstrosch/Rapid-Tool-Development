## Parse PE - Python Script

The purpose of this script is to parse a PE file and display general information about it's structure.  My primary goal was to learn more Python and to better understand abnormalities in PE files (typically used in malware).  I also want to be able to do more analysis via scripting, this greatly enhances my ability to do that.  I initially wanted the script to be able to accomplish the following:

* Create structures identical to those found in Windows header file
* Parse a PE and display any desired information, such as number of sections
* Display import symbols - imported library and function name (and/or ordinal)
* Integrate PiED signatures

I found it more of a challenge to do this in Python than I had expected.  [pefile](https://github.com/erocarrera/pefile) appears to be the dominate PE Parsing Python module and I ended up using some of it's code to help with my parsing efforts.  I wanted to design a script that could process a single file or an entire directory of files, determing which are PE and which are not.

# Current Status

The current status of the tool is that I parses a PE through the sections table and the individual sections, mapping sections of the file into structures for easier access.  However, I was unable to parse the imports and integrate PiED signatures.

# Usage

```
$ python read_pe.py -f <filename>
```