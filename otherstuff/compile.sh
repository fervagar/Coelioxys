#!/bin/bash

if [ $# -eq 0 ]; then
	echo "1 Argument is needed (name of the asm source code file)"
else
	EXT="${1##*.}"
	if [ $EXT == "s" ]; then
		FILENAME=${1%.*}
	else
		FILENAME=$1
	fi
	as -gstabs $FILENAME.s -o $FILENAME.o
	if [ $? -eq 0 ]; then
		ld $FILENAME.o -o infector;
		rm $FILENAME.o
	fi
fi
