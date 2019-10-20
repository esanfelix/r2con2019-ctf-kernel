# Kernel pwnable for r2con 2019 CTF 

This repository contains the challenge I contributed the r2con 2019 CTF. The 
challenge was not solved during the CTF, so I decided to also host it on 
github.

The repository contains the following folders:

* `challenge/` contains the files provided to the CTF participants. This is 
the only directory with contents at the moment.

* `source/`: contains the source code of the `socks.ko` module running in the 
challenge VM. By mistake I also left a half-finished v2 module inside the VM
filesystem that was not relevant to the challenge.

* `solution/`: contains a write-up of my solution as well as two differnt 
exploits to be used for reference purposes.