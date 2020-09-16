Stage 7:

A). I have used the project B code given by TA for my project C and have used functions from the following references.
Michael Kerrisk, Linux man pages online. http://man7.org/linux/man-pages/index.html
roman10, November 27, 2011. http://www.roman10.net/2011/11/27/how-to-calculate-iptcpudp-checksumpart-2-implementation/
TCP checksum: www.binarytides.com/raw-sockets-c-code-linux.

B). Yes
C). Loss of connection can happen because Kernel will try to control the connection by sending RST packets.
D). Since TCP is connection oriented and if no application is listening Kernel generate RST, while UDP and ICMP are connectionless.  

Info : code an be compiled using make command 
Execution : sudo./projc config.dat.stage7
Kill process: sudo ./kill -9 projc
