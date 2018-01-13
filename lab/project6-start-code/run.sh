#!/bin/bash
umount mnt
dd if=/dev/zero of=disk.img bs=4K count=10000
make clean && make
./p6fs disk.img mnt -o logfile="log"
sleep 1
cat log
