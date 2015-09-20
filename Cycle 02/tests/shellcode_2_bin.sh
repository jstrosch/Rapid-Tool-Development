#!/bin/bash

function usage
{
	echo ""
	echo "[*]USAGE: ./shellcode_2_bin.sh -i [Input Shellcode]"
	echo ""
	echo "[!] REQUIRED"
	echo -e "\t-i  Input (text) file containing the shellcode."
	echo ""
}

shellcode=
binary=

while getopts ":f:" OPTIONS
do
    case $OPTIONS in
    f)     shellcode=$OPTARG;;
    ?)     printf "Invalid option: -$OPTARG\n" $0
                  exit 2;;
    esac
done

shellcode=${shellcode:=NULL}
binary="$shellcode.bin"

# Check for SHELLCODE source
if [ $shellcode = NULL ]; then
	usage
else

	echo "[*] Filtering Shellcode..."
	cat $shellcode | grep '"' | tr -d " " | tr -d "\n" | sed 's/[\"x.;(){}]//g' >> $shellcode.tmp

	echo "[*] Converting to binary w/ XXD..."
	xxd -r -p $shellcode.tmp $binary

	rm $shellcode.tmp
	echo -e "[*] Complete\n"

fi