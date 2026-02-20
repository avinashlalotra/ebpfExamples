#!/bin/bash
ls -id $1 | awk '{printf "%016x\n", $1}' | \
sed 's/\(..\)/\1 /g' | \
awk '{for(i=NF;i>=1;i--) printf "0x%s ", $i; print ""}'
