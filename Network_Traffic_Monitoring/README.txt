Assignment 6
////////////////////////////////////////////////////////////

Amplianitis Konstantinos 
gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
////////////////////////////////////////////////////////////

In this Assignment the concept was to create a programm
that analyses a .pcap file and prints all the info 
about the packages and the total statistics of it.

The programm has been written in the monitor.c
////////////////////////////////////////////////////////////


monitor.c
////////////////////////////////////////////////////////////

In this file I implement the whole Assignment. 

The function can be called either with the flag -h
or with -r filename.pcap. In any other case, an error 
message is getting printed. 

In order to open the file properly I used the function 
pcap_open_offline that is implemented in the pcap.h lib.

After the opening of the file in order to process the packages
i used the function pcap_loop which is also implemented in the 
pcap.h lib. In order for this function to work, I had to implement
a function called packet_Handler that has specific arguments given by 
the same lib. Into the packet_Handler I followed the instructions given
by varius web links about how to take the tcp headers or the udp headers
how to check the packet protocol etc. To find the higher protocols I opened 
the same file in wireshark in order to check which of the higher protocols exist.
I found that I can check the higher protocol through the ports that the packet is getting
sent or is getting received. Having that on my head I implemented a function that 
finds the higher protocol based on the above rule.


In order to check for network flows created or existing, at start I created a new struct
called network_flow (typedef netflow) that contains all the information that has been asked.
The struct has also a pointer to the next one in order to create a linked list and be able to
run through the list of existing netflows, making the process of checking easier. Into the 
function there is a while loop that is running through the existing netflows and inside there is
a check about whether the existing packet is a part of an existing netflow or not. To check that
I check that there is no netflow that has the same IPs(dest/source) the same ports(source/dest)
and the same protocol.


In order to check for retransmission I rememebered from previous courses (Networks I) that UDP protocol
does not support retransmission. So this makes me know already that there is no UDP retransmissions in the
.pcap file. 

TCP does support retransmission though.
In order to find whether a packet is retransmitted or not I check the wireshark documentation in that link
https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html

Reading that I decided to create a second struct that holds all the tcp packets in order to be able to find the 
information i wanted. So there is a struct in my code that is called tcp_packet_info (typedef tcp_packet). Then i 
implement a function that creates a linked list of tcp_packet to make checking easier.To check if a packet is retransmitted 
or not I check if the packet is not a keep-alive packet. Then I check if there is a packet that has almost identical
characteristics as the one that i am examining. If that is the case, the only thing i have to do is to check if the expected
sequence number is bigger that the sequence number of the packet. If thats the case, the function prints under the packet the 
word "Retransmission".

After all these checks the packet_Handler prints some crucial info about the packet it analyses.
The info contain, IPv4 (source/dest), port(source/dest), protocol(TCP/UDP), TCP header length (bytes), Payload length(bytes) higher
protocol, and optionaly based on the results of the above function("Retransmission").


In the end and after the exit of the packet_process(the function who calls the pcap_loop) the programm prints the statistics of the file.
In order to keep track easily of specific amounts the values are getting declared as global variables. This has been done to avoid having so 
many pointers along the code that will make the code a lot more complicated both in understanding and in implementation. 


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
Makefile

In the Assignment folder there is a make file in order to be able to compile the code and with make clean to remove the executables.
In order for the code to pass the compilation i included as a flag the -lipcap