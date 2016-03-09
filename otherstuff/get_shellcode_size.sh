#!/bin/bash

printf 'Shellcode size: 0x%x\n' `echo $(objdump -d "$1" | grep "^ "|awk -F"[\t]" '{print $2}') | wc | awk '{print$2}'`

