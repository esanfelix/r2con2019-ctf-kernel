This folder contains the challenge as provided to the CTF participants,
plus this README file. The challenge server is down, but you can still 
try to write the exploit locally against the VM provided here (see 
`run.sh`).

The provided challenge description was as follows:

```
Pull up your socks

Be careful with moths, can make small holes in your socks.

r2 has new socks, and they are in kernel land! Pwn the kernel
in this challenge and read the flag off /flag.txt

nc xxx.xxx.xxx.xxx 31337
```

And the following two hints were published during the CTF in order:


```
Take a look at how socks are allocated
```

```
Once you got arbitrary write, you can use the modprobe_path trick, similar to: https://vishnudevtj.github.io/notes/1118daysober
```


