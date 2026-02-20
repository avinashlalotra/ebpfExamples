#!/bin/bash

# Compile and load the prog

echo "[+] Compiling and loading the prog"
make all
make load

# Create a directory to watch

echo "[+] Creating a directory to watch"
mkdir -p folder

# Load the directory inode into the map for lookup
echo "[+] Loading the directory inode into the map for lookup"
make map F=folder


# Show log 

echo "[+] Spawning new shell in folder..."
gnome-terminal -- bash -c "cd folder; exec bash"
echo "[+] Create some fles in the folder"
echo "[+] Showing the logs"
echo "[+] Press Ctrl+C to stop the logs"

make showlog



# Unload the prog
echo "[+] Unloading the prog"
make unload
rm -r folder

