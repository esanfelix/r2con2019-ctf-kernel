#!/bin/sh

qemu-system-x86_64 -cpu qemu64,-smep,-smap \
	-m 64 \
	-kernel ./kernel \
	-nographic \
	-append "console=ttyS0 quiet" -initrd ./initramfs \
	-monitor /dev/null
