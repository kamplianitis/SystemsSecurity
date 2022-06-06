#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <unistd.h>

#define PCAP_BUF_SIZE	1024
#define PCAP_SRC_FILE	2

// struct of network flow 
typedef struct networkFlow
{
	char *IPv4s;
	char *IPv4d;
	u_int source_port;
	u_int dest_port;
	int protocol;
	struct networkFlow *next; // to create a linked list
} netflow;


// struct of tcp_packets that are in the .pcap file. I created that struct in order 
typedef struct tcp_packet_info
{
	char *IPv4s;
	char *IPv4d;
	u_int source_port; 
	u_int dest_port;
	int protocol;
	int segment_size; // segment size is the size of the packet header included
	u_int32_t sequence_num; 
	u_int32_t expected_sequence_num;
	u_int32_t acknowledge_num;
	// flags needed taken from the tcphdr struct
	uint16_t syn;
	uint16_t fin;
	uint16_t rst;
	struct tcp_packet_info *next; // to create a linked list
}tcp_packet;

// global variables. I made them global cause it's easier to prints the stats in the end without updating pointers all the time
u_int total_packets =0; // total packets counter
u_int tcp_packets=0; // total packets that are tcp 
u_int udp_packets=0; // total packets that are udp
u_int no_tcp_udp_packets=0; // total other packets
u_int total_netflows=0; // netflows created in the packet capturing
u_int tcp_netflows=0; // tcp netflows
u_int udp_netflows=0; // udp netflows
u_int total_tcp_bytes=0; // bytes transfered via TCP 
u_int total_udp_bytes=0; // bytes transfered via UDP

// heads of the two lists
netflow *netflowHead;
tcp_packet *tcpListHead;

/*
	Void function
	Prints the usage of the programm in case something goes wrong or the help flag is set
*/
void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./packet_monitor -r Packet capture file name (e.g. test.pcap)\n"
		   "Options:\n"
		   "-h, Help message\n\n"
		   );
	exit(1);
}

/*
	void function

	Arguments
	arg0: source_Ip -> the source Ip of the new packet.
	arg1: dest_IP -> the destination Ip of the new packet.
	arg2: sourcePort -> the source port of the new packet. 
	arg3: destPort -> the destination port of the new packet.
	arg4: protocol -> the protocol of the new packet.
	arg5: seg_size -> the size of the segment of the packet. This size contains the tcp header size and the payload size cause it should according to wireshark.
	arg6: seq_num -> The sequence number of the new packet.
	arg7: ack_num -> The acknowledge number of the new packet.
	arg8: fin -> flag about the keepaliveness of the packet.
	arg9: rst -> flag about the keepaliveness of the packet.
	arg10: syn -> flag about the keepaliveness of the packet.

	Functionality
	The function checks if the new packet that came in is a retransmission or not. To do that I keep the rules of wireshark that are described in the link bellow.
	https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html

*/	
void 
check_retransmission(char *source_Ip, char *dest_Ip, u_int sourcePort, u_int destPort, int protocol, int seg_size, uint32_t seq_num, uint32_t ack_num, uint16_t fin ,uint16_t rst, uint16_t syn)
{
	// in case it's the first packet there is no way i can check for retransmission so the function returns
	if(tcp_packets == 1)
	{
		return;
	}
	else // check for retransmission
	{
		tcp_packet *temp;
		temp = tcpListHead;

		// check for the packet beeing keepalive
		if(!(seg_size == 0 || seg_size == 1) && !(rst == 1 || fin == 1 || syn ==1)) // not a keepalive packet so i can check for everything else
		{
			// now check if there is a packet with the same characteristics in the tcp packet list
			while(temp->next != NULL)
			{
				if((strcmp(temp->IPv4s, source_Ip) == 0) && (strcmp(temp->IPv4d, dest_Ip)== 0) && (temp->source_port == sourcePort) && (temp->dest_port == destPort) && (temp->protocol == protocol) 
				&& (temp->segment_size == seg_size) && (temp->sequence_num == seq_num) &&(temp->acknowledge_num == ack_num)) // if this is true the packets are almost identical
				{
					// calculate the seqence number
					if(temp->expected_sequence_num > seq_num) // check for the last condition
					{
						printf("Retransmission\n");
						printf("---------------------\n");
						return; // already found that is a retransmission so no need to search more
					}
				}
				temp = temp->next;
			}	
		}
	}
}



/*
	void function

	Arguments
	arg0: source_Ip -> the source Ip of the new packet.
	arg1: dest_IP -> the destination Ip of the new packet.
	arg2: sourcePort -> the source port of the new packet. 
	arg3: destPort -> the destination port of the new packet.
	arg4: protocol -> the protocol of the new packet.
	arg5: seg_size -> the size of the segment of the packet. This size contains the tcp header size and the payload size cause it should according to wireshark.
	arg6: seq_num -> The sequence number of the new packet.
	arg7: ack_num -> The acknowledge number of the new packet.
	arg8: fin -> flag about the keepaliveness of the packet.
	arg9: rst -> flag about the keepaliveness of the packet.
	arg10: syn -> flag about the keepaliveness of the packet.

	Functionality
	The function creates a linked list of all the tcp packets that have been recorded to the .pcap file. It uses the tcp_packet_info_struct. It gets called before the check for 
	retransmission because the check retransmission while loop has a condition of temp->next != NULL. This means that the last packet will not get checked(In that case the last will be 
	the new one)
*/	
void 
addTcpPacket(char *source_Ip, char *dest_Ip, u_int sourcePort, u_int destPort, int protocol, int seg_size, uint32_t seq_num,uint32_t ack_num, uint16_t fin ,uint16_t rst, uint16_t syn)
{
	if(tcp_packets == 1) // I check with one cause the min I find that there is a tcp packet the counter is getting increased.
	{
		// in case the above condition is met i just assign the values to the head of the list
		tcpListHead = malloc(sizeof(tcp_packet));
		
		tcpListHead->IPv4s = source_Ip;
		tcpListHead->IPv4d = dest_Ip;
		tcpListHead->source_port = sourcePort;
		tcpListHead->dest_port = destPort;
		tcpListHead->protocol = protocol;
		tcpListHead->segment_size = seg_size;
		tcpListHead->sequence_num = seq_num;
		tcpListHead->acknowledge_num = ack_num;
		tcpListHead->fin = fin;
		tcpListHead->rst = rst;
		tcpListHead->expected_sequence_num = 0;
		tcpListHead->syn = syn;
		tcpListHead->next = NULL;
	}
	else // case the list already has a head
	{
		tcp_packet *temp = tcpListHead; // create a temp to roam around the list
		while(temp->next != NULL) // go in the end of the list to add the packet
		{
			temp = temp->next;
		}
		// now that i am in the end of the list i will create a new node and put it in the end of the list
		tcp_packet *temp2 = malloc(sizeof(tcp_packet));
		temp2->IPv4s = source_Ip;
		temp2->IPv4d = dest_Ip;
		temp2->source_port = sourcePort;
		temp2->dest_port = destPort;
		temp2->protocol = protocol;
		temp2->segment_size = seg_size;
		temp2->sequence_num = seq_num;
		temp2->acknowledge_num = ack_num;
		temp2->expected_sequence_num = temp->sequence_num + seg_size;
		temp2->fin = fin;
		temp2->rst = rst;
		temp2->syn = syn;
		// update the end of the list
		temp2->next = NULL;
		temp->next = temp2; 
	}
}

/*
	Void function

	Arguments:
	arg0: IPv4s -> The IPv4 value of the source.
	arg1: IPv4d -> The IPv4 value of the destination.
	arg2: source_port -> The port of the source.
	arg3: dest_port -> The port of the destination.
	arg4: protocol -> The protocol of the packet.

	Functionality:
	The function checks if the packet that is getting examined creates a new netflow or is a part of an existing one. In order to check that I have to check whether there
	has been detected any packets with the same values( given as arguments) before. In case that is, the packet is a part of an existing netflow. In any other case, the packet
	creates a new netflow so the values are getting saved in a list of netflows for future use(Check of any packets in the same netflow). If the netflow is new, the global value 
	that counts the amount of netflows in the packet gets increased.
*/
void 
check_netflow_list(char* IPv4s, char*  IPv4d, u_int source_port,u_int dest_port ,u_int protocol)
{
	if(total_netflows == 0) // in case of the first packet
	{
		// create space for storing the head of the list
		netflowHead = malloc(sizeof(netflow));
		// assign the values 
		netflowHead->IPv4s = IPv4s;
		netflowHead->IPv4d = IPv4d;
		netflowHead->source_port = source_port;
		netflowHead->dest_port = dest_port;
		netflowHead->protocol = protocol;
		netflowHead->next = NULL;
		total_netflows++;
		if(protocol == 6) // up the tcp udp netflows counter
		{
			tcp_netflows +=1;
		}
		else
		{
			udp_netflows +=1;
		}
		printf("\n Head created\n");
		printf("--------------------------\n");
	}
	else 
	{
		// search in the netflows list for existing netflows 
		netflow* temp = netflowHead;
		while(temp != NULL)
		{
			if(strcmp(IPv4s, temp->IPv4s)==0 && strcmp(IPv4d, temp->IPv4d)==0 && temp->source_port == source_port && temp->dest_port == dest_port && temp->protocol == protocol)
			{
				printf("Netflow already exists\n");
				printf("--------------------------\n");
				return; // in case there is an existing netflow retrurn from the function so the following code will not get executed
			}
			if(temp->next == NULL) // i used this condition to check whether i am on the end of the list or not 
			{
				break; // exit from the for loops
			}
			else
				temp = temp->next; // go to the next node
		}
		// in case we exited the end of the list -> there is not an existing netflow already we assign the values of the new netflow 
		// in the end of the list
		netflow* temp2 = malloc(sizeof(netflow));
		temp2->IPv4s = IPv4s;
		temp2->IPv4d = IPv4d;
		temp2->source_port = source_port;
		temp2->dest_port = dest_port;
		temp2->protocol = protocol;
		// update the end of the list to include the new netflow
		temp2->next = NULL;
		temp->next = temp2;
		//increase the counters
		total_netflows++;
		if(protocol == 6) // up the tcp udp netflows counter
		{
			tcp_netflows +=1;
		}
		else
		{
			udp_netflows +=1;
		}
		printf("New netflow created\n");
		printf("--------------------------\n");
	}
}



/*
	void function

	Arguments:
	arg0: source_Port -> the source port of a packet.
	arg1: dest_Port -> the destination port of a packet.
	arg2: protocol -> the protocol of the packet.

	Functionality:
	In order to find the higher protocols I searched for protocols through wireshark. Then I googled the most common ports that these protocols use. With an if statement based on 
	protocol (the reason is that some higher protocols are made in both tcp udp) I decide based on source/dest port the higher protocol of the packet
*/
void 
check_Higher_Protocol(u_int source_Port, u_int dest_Port, int protocol)
{	
	if(protocol == 6) // tcp packet
	{
		if(source_Port == 80 || dest_Port == 80)
		{
			printf("Protocol: HTTP\n");
		}
		else if(source_Port == 443 || dest_Port == 443) // TLSv1
		{
			printf("Protocol: HTTPS(TLSv1/SSLv2)\n");
		}
		else if((source_Port == 139 || dest_Port == 139) || (source_Port == 445 || dest_Port == 445))
		{
			printf("Protocol: SMB/NBSS \n");
		}
		else if((source_Port == 569 || dest_Port == 569) || (source_Port == 1863 || dest_Port == 1863))
		{
			printf("Protocol: MSNMS\n");
		}
		else
		{
			printf("Protocol: TCP\n");
		}
	}
	else if(protocol ==17) // udp packet
	{
		if(source_Port == 137 || dest_Port == 137)
		{
			printf("Protocol: HTTP\n");
		}
		else if(source_Port == 1900 || dest_Port == 1900)
		{
			printf("Protocol: SSDP\n");
		}
		else if((source_Port == 67 || dest_Port == 67) || (source_Port == 68 || dest_Port ==68))
		{
			printf("Protocol: DHCP\n");
		}
		else if((source_Port == 5355 || dest_Port == 5355) || (source_Port == 5354 || dest_Port ==5354))
		{
			printf("Protocol: LLMNR\n");
		}
		else if((source_Port == 137 || dest_Port == 137) || (source_Port == 138 || dest_Port ==138))
		{
			printf("Protocol: NBNS\n");
		}
		else if(source_Port == 17500 || dest_Port == 17500)
		{
			printf("Protocol: DB-LSP-DISK\n");
		}
		else if(source_Port == 53 || dest_Port == 53)
		{
			printf("Protocol: DNS\n");
		}
		else
		{
			printf("Protocol: UDP\n");
		}
	}
	else
	{
		printf("Wrong protocol");
	}
}


/*
	void function

	packet_handler has specific arguements in the library so i use them to be able to use the pcap_loop function

	Functionality:
	The packet_Handler is a function that is getting called in the pcap_loop in order to process each packet of the .pcap file individualy. The function at the starts increases
	the counter that is responsible of counting the total packets in the file. Then checks if the packet is a IP packet since both TCP and UDP packets are IP protocols. After the
	first check, the second check comes checking if the packet is a TCP, a UDP, or other. In case there is a TCP packet I take all the values that are required to get printed, I 
	check if netflow already exists, I add the packet to the tcp packet list and in the end I check whether the packet is a retransmission or not. In case the packet is a UDP packet
	I do basically the same procedure except I do not need to keep the udp packets and check for retransmission cause UDP protocol does not support this functionality. In any case I
	update the corresponding counter. If the packet is neither TCP nor UDP, the packet is getting skipped.

*/

void 
packet_Handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *buffer)
{
	total_packets += 1; // increase the total packets by one
	struct ether_header *eth_header; 

	eth_header = (struct ether_header* ) buffer;
	
	// check ethertype for being ipv4 or ipv6 protocol
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) 
	{
		printf("Not even ip packet!!\n");
		no_tcp_udp_packets +=1; 
		return;
    }
	else
	{
		//take the ip header
		const struct ip* ipHeader = (struct ip*)(buffer + sizeof(struct ether_header)); 
		
		// create the char cause in both ways i need them and i take them from the ip header
		char sourceIP[INET_ADDRSTRLEN];
    	char destIP[INET_ADDRSTRLEN];

		// check if the protocol is tcp
		if(ipHeader->ip_p == IPPROTO_TCP)
		{
			tcp_packets +=1;
			
			struct tcphdr *tcpHeader = (struct tcphdr*)(buffer + sizeof(struct ether_header) + sizeof(struct ip));
			// take the header length
			int tcpheader_length = tcpHeader->doff*4;  
            
			// take the ports
			u_int sourcePort = ntohs(tcpHeader->source);
            u_int destPort = ntohs(tcpHeader->dest);
            
			// payload length
			int dataLength = packet_header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
			int size = packet_header->len - (sizeof(struct ether_header));
			// update the total tcp bytes transfered.
			total_tcp_bytes += dataLength;

			// take the source and destination ip that is needed
			inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        	inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
			
			// print details of the packet
			printf("Source Port:%d \t DestPort:%d\t Protocol: TCP\t TCP Header: %d bytes\t Payload length: %d bytes\t  Source Ip: %s \t Dest Ip: %s\n", sourcePort,destPort,tcpheader_length,dataLength, sourceIP, destIP);
			check_Higher_Protocol(sourcePort,destPort, 6);
			// check for netflow
			check_netflow_list(sourceIP, destIP,sourcePort,destPort,6);// tcp protocol is 17 in assigned numbers
			// first i add the packet to the list of tcp packets
			addTcpPacket(sourceIP, destIP,sourcePort,destPort ,6, size,tcpHeader->th_seq,tcpHeader->th_ack,tcpHeader->fin ,tcpHeader->rst , tcpHeader->syn);
		
			// to check retransmission of a tcp packet i need to create a struct of tcp packets and check specific parameters according to wireshark 
			check_retransmission(sourceIP, destIP,sourcePort,destPort ,6, size, tcpHeader->th_seq,tcpHeader->th_ack, tcpHeader->fin , tcpHeader->rst , tcpHeader->syn);
			
		}
		else if(ipHeader->ip_p == IPPROTO_UDP) // i know that udp does not support retransmision so there is no point of searching for it.
		{
			udp_packets +=1;
			struct udphdr *udpHeader = (struct udphdr*)(buffer + sizeof(struct ether_header) + sizeof(struct ip));
			
			// take the porst
			u_int sourcePort = ntohs(udpHeader->source);
            u_int destPort = ntohs(udpHeader->dest);

			// take the ips of the source and of the destination
			inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        	inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

			// same way with tcp for taking the content length
			int dataLength = packet_header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
			
			// update the udp bytes counter
			total_udp_bytes += dataLength;
			// print details of the packet
			printf("Source Port:%d \t DestPort:%d\t Protocol: UDP\t UDP Header: 8 bytes\t Payload length: %d bytes\t  Source Ip: %s \t Dest Ip: %s\n", sourcePort,destPort,dataLength, sourceIP, destIP);
			check_Higher_Protocol(sourcePort, destPort, 17);
			// check for netflow
			check_netflow_list(sourceIP, destIP,sourcePort,destPort,17); // udp protocol is 17 in assigned numbers

			// since udp doest not support retransmission protocol all the above functions used for the tcp are not needed and nothing is getting done
		}
		else
		{
			// since i do not decode these type of packets i do not  
			no_tcp_udp_packets +=1;
			return;
		}

	}
}

/*
	void function

	arg0: optarg -> the name of the packet for checking

	Functionality:
	The packet process is basically a function that opens the .pcap file using the pcap_open_offline and with the help of pcap loop (which calls packet_Handler) it processes
	all the packets that are included there.
*/
void 
packet_process(char *optarg)
{

	// char array to hold the error message in case of any
	char errbuf[PCAP_ERRBUF_SIZE];
    //char source[PCAP_BUF_SIZE];
	//int i, maxCountSyn = 0, maxCountHttp = 0, maxIdxSyn = 0, maxIdxHttp = 0;

	// opening the file 
	pcap_t *fp = pcap_open_offline(optarg,errbuf);
	if (fp == NULL) {
	    fprintf(stderr, "\n Oppening file failed: %s\n", errbuf);
	    exit(-1);
    }

	// now i have to check for the packets. I use pcap_loop to process the file
	if(pcap_loop(fp,0, packet_Handler, NULL) < 0) // I put 0 to tell the function there is no limit
	{
		fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
		exit(-1);
	}
}

/*
	void function

	Functionality:
	The function is getting printed after the process ended. It prints how many packets have been detected (analyzed in tcp,udp), how many flows have been created, how many of them are tcp/udp and the 
	total payload (also getting analysed in tcp/udp).
*/
void 
print_pcapfile_stats()
{
	printf("\n Pcap File stats\n");
	printf("-------------------\n");
	printf("Total number of netflows captured: %d network flows\n", total_netflows);
	printf("Number of TCP netflows captured: %d TCP network flows\n", tcp_netflows);
	printf("Number of UDP netflows captured: %d UDP network flows\n", udp_netflows);
	printf("Total packets received: %d packets\n",total_packets);
	printf("Total TCP packets received: %d TCP packets\n", tcp_packets);
	printf("Total UDP packets received: %d UDP packets\n", udp_packets);
	printf("Total bytes of TCP packets: %d bytes \n", total_tcp_bytes);
	printf("Total bytes of UDP packets: %d bytes\n",total_udp_bytes);
}

int
main(int argc, char *argv[])
{
    if(argc <2)
    {
        printf("Not enough arguments!!!!");
        usage();
    }
	
	int ch;

	while ((ch = getopt(argc, argv,"hr:")) != -1)
	{
		switch (ch)
		{
		case 'h':
			usage();
			break;
		case 'r':
			packet_process(optarg);
			// print the file stats 
			print_pcapfile_stats();
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;	
	return 0;
}