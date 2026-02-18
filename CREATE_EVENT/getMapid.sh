#!/bin/bash
sudo bpftool map list | awk '/InodeMap/ {sub(":", "", $1); print $1}'
