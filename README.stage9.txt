Stage 9:

A). I have used the project B code given by TA for my project C and have used functions from the following references.
Michael Kerrisk, Linux man pages online. http://man7.org/linux/man-pages/index.html
roman10, November 27, 2011. http://www.roman10.net/2011/11/27/how-to-calculate-iptcpudp-checksumpart-2-implementation/
TCP checksum: www.binarytides.com/raw-sockets-c-code-linux.

B). I was unable to implement the timer at the router but I have completed the rest in which I can easily identify the failure and can recover from it without any packet loss. I have used extra buffer to save the packet which might be dropped and retransmit it after creating a new circuit.  

Info : code an be compiled using make command 
Execution : sudo./projc config.dat.stage9
Kill process: sudo ./kill -9 projc
