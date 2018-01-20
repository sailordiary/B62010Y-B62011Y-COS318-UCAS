#!/bin/bash
sudo umount mnt
dd if=/dev/zero of=image bs=4096 count=1 conv=notrunc
make clean && make
./p6fs disk.img mnt -o logfile="log"
sleep 1
cat log
