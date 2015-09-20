## PyDis - Python x86 Dissassembler

The purpose of this script is to leverage the Capstone framework to allow for disassembly of x86-based...

# Dependencies

In order to run this script, you will need to have the Capstone framework installed on your system.  Capstone can be found at (http://www.capstone-engine.org/) with installation instructions located at: [Docs](http://www.capstone-engine.org/documentation.html)

# Current Status

This script is able to generate an assembly listing from provided shellcode using the Capstone framework.  Additionally, this script can search a PE32 (EXE or more likely a DLL) for a supplied instruction (ex: jmp esp).  Searching is still experimental though :)

# Usage

```
To generate assembly from shellcode:
$ python pyDis.py -f <shellcode>

To search a module for a specific instruction:
$ python pyDis.py -s <instruction> -m <PE32 to search>
```