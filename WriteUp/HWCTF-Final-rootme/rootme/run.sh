#!/bin/bash
qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel /files/bzImage \
    -append 'console=ttyS0 oops=panic panic=1 init=/init nokaslr' \
    -monitor /dev/null \
    -initrd /files/root.cpio