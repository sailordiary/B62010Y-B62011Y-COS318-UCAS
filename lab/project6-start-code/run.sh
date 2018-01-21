#!/bin/bash
sudo umount mnt
rm image
dd if=/dev/zero of=image bs=4096 count=1 conv=notrunc
make clean && make
./p6fs image mnt -o logfile="log"
sleep 1
cat log
