
//Coding:
//Sniffer.h

#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<stdio.h>
#include<stdlib.h>
#include<sniffer.h>
#include<sys/socket.h>
#include<features.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<string.h>
#include <time.h>
#define MAXLENGTH 2048 // Sets the length of buffer in which we are going to store the packet
#define MAX_PACKETS 50000 // Maximum number of packetsthat can be captured
#define TIMEOUT 1 /* Time after which gtk_main is
invoked(To check for if a new packet has been captured and 
 print it on the GUI 
interface if there is one)*/
#define MAXINTERFACES 10 // Maximum number of network interfaces
#define PDFVIEWER "okular"
//The default pdf viewer
/* Returns 1 if the packet captured was according to the filter set by user
 * Also is a general function to fill the structure entries of the packet by calling the 
specialised functions

 * Is the soul of the Code for decoding of packets
 */
int PrintPacketInformation(unsigned char *,int);
//Fills the fields of the "packe" structure in case of IPv4|TCP
void PrintPacketInformation_TCP(unsigned char *, int);
//Fills the fields of the "packe" structure in case of IPv4|UDP
void PrintPacketInformation_UDP(unsigned char *, int);
//Fills the fields of the "packe" structure in case of IPv4|ICMP
void PrintPacketInformation_ICMP(unsigned char *, int);
//Fills the fields of the "packe" structure in case of ARP and returns 1 if all the fields required by user are satisfied
int PrintPacketInformation_ARP(unsigned char *, int);
//Fills the fields of the "packe" structure in case of IPv6|UDP
void PrintPacketInformation_UDP_IPv6(unsigned char *, int);
//Fills the fields of the "packe" structure in case of IPv6|TCP
void PrintPacketInformation_TCP_IPv6(unsigned char *, int);
//Fills the fields of the "packe" structure in case of IPv6|ICMP
void PrintPacketInformation_ICMP_IPv6(unsigned char *, int);
//Converts a hexadecimal character to its decimal value
int xtod(char); 
//Converts a hexadecimal string to its decimal value
int hextoint(char *, int);
//Prints the packet
void Printpacket();
//Dump the hex code of packet into the hex_dump field of "packe"
void Printhexdump(unsigned char *,int);
typedef struct packe{

int index; // Index of the captured packet
int size; // Size of the frame received
double arrival_time; // Time of arrival
char source[40]; // Source Address
char destination[40]; // Destination Address
char protocol[10]; // Protocol used at the topmost layer i.e. the deepest in the packet
char protocol_hierarchy[80]; // Encapsulation Sequence i.e. IPv4:TCP:FTP
char relevant[100]; // Something really important about the packet
char less_relevant[400]; // General and less relevant information obtained from the packet
char hex_dump[2048]; // The packet printed in Hex format
}pack;

// Global variables
int count_printed; // Number of packets captured and printed till now
// User defined filters
char protocol[15] = "all"; // protocol to sniff
char source_ip[40] = ""; // Source address to sniff on
char destination_ip[40] = ""; // Destination address to sniff on
char source_MAC[40] = ""; // Source address MAC Address to sniff on
char destination_MAC[40] = ""; // Destination MAC address to sniff on

pack packet_struct[MAX_PACKETS]; // Initialize the structure packet for MAX_PACKETS number of packets
// Packet Sniffer that takes the argument name of interface on which trafic is to analysed
int main(int argc, char **argv)
{
// declaration of variables 
int rawsock; // raw socket descriptor
int len; // length of packet 
int proto;
int state = 1; // Continue sniffing packet
till state != 0
char buffer[MAXLENGTH];
struct sockaddr_ll sll; // structure of type sock address 
struct ifreq req; // structure  required to request a particular interface for socket ioctl commands
int t; // Variable to chaeck whether the packet captured was according to our needs
struct timeval tv1, tv2; // Variables required to calculate the time of arrival of packet w.r.t starting the capture 
// Initializing Global variables
count_printed = 0;
// Set the protocol family which are to be captured in the protocol field of Socket
// All Protocol
if (strcmp(protocol,"all") == 0) 
proto = ETH_P_ALL;
// IPv4 Protocol
if (strcmp(protocol,"ipv4") == 0 || strcmp(protocol,"ipv4|udp") == 0 || strcmp(protocol,"ipv4|tcp") == 0 || strcmp(protocol,"ipv4|icmp") == 0) 
proto = ETH_P_IP;

// IPv6 Protocol
if (strcmp(protocol,"ipv6") == 0 || strcmp(protocol,"ipv6|udp") == 0 || strcmp(protocol,"ipv6|tcp") == 0 || strcmp(protocol,"ipv6|icmp") == 0) 
proto = ETH_P_IPV6;
// ARP Protocol
if (strcmp(protocol,"arp") == 0) 
proto = ETH_P_ARP;
/* Creating the packet socket 
 * Only a root owner can run this line because only have the capability to 
open packet sockets(that is why we CAN RUN THIS 
 CODE ONLY WITH ROOT PERMISSIONS).
 * Packet Sockets with socket_type to be SOCK_RAW allow us to bypass 
the network stack so that we get the packet directly 
 delivered to us(without any header ripped off).
 * PF_PACKET interface allows us to send/receive packets directly at the 
device driver level, thus all packets received 
 will be complete with header and data
 * The third argument of creating a socket specifies the protocol of which 
packets are to be filtered
 */
if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(proto)))== -1)
{
perror("Error in creating raw socket: ");
exit(-1);
}
//Initialize the structures
bzero(&sll, sizeof(sll));
bzero(&req, sizeof(req));
/* IFNAMSIZ is a constant defined in <net/if.h> file which defines the 
maximum buffer size value needed to hold an interface
 name (Its value is defined to be 16 in the header file)*/
/* strncpy is a safe way of copying than strcpy(buffer overflow) and hence 
IFNAMSIZ is a real boon */
 
/* We specify the device we want to affect by the ifr_name field and hence 
we are copying the interface name as argument to 
 the required field */ 
 
strncpy((char *)req.ifr_name, argv[1], IFNAMSIZ);
// First Get the Interface Index 
/* SIOCGIFINDEX : Request to retrieve the interface index into the 
ifr_ifindex field of ifreq structure*/
if((ioctl(rawsock, SIOCGIFINDEX, &req)) == -1)
{
printf("Error while retrieving Interface index !\n");
exit(-1);
}
sll.sll_family = AF_PACKET;
/* For binding the device to some interface, we need to the sll_ifindex field 
of sockaddr_ll structure to the interface 
 index of the device*/ 
sll.sll_ifindex = req.ifr_ifindex;
sll.sll_protocol = htons(proto); 
// Finally,binding the socket to the given interface 
if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
{
perror("Error binding raw socket to interface\n");
exit(-1);
}
// Record this time i.e. the time just before we start capturing the packets
gettimeofday(&tv1, NULL);
// Start Sniffing and print the details of every packet 
while(state)
{
if((len = recvfrom(rawsock, buffer, MAXLENGTH, 0, NULL, 
NULL)) == -1)

{
perror("Recv from returned -1: ");
exit(-1);
}
// Time after capturing the packet
else
{
gettimeofday(&tv2, NULL);
if (count_printed == MAX_PACKETS)
// Stop printing the packets beyond MAX_PACKETS
state = 0;
sprintf(packet_struct[count_printed].less_relevant,"Frame Size :%d bytes \n",len);
// Call the function to put the relevant details into the packet fields
t = PrintPacketInformation(buffer, len);
// Packet has been received successfully and is according to filters set by the User!! 
if (t)
{ 
packet_struct[count_printed].size = len;
packet_struct[count_printed].index = count_printed + 1;
packet_struct[count_printed].arrival_time = ((double) (tv2.tv_usec - tv1.tv_usec)/1000000 + (double) (tv2.tv_sec - tv1.tv_sec));
Printpacket();
Printhexdump(buffer,len);
count_printed ++;
}
else
{
bzero(packet_struct,sizeof(pack));
}
}
//Initialize the buffer again for proper overwriting
bzero(buffer,MAXLENGTH);
}

//Close the socket
//The vale 2 specifies that we are closing the socket for both send and receive
shutdown(rawsock,2);
return 0;
}
// Convert a hexadecimal character to int
int xtod(char c) {
if (c >= '0' && c <= '9') 
return c - '0';
if (c >= 'A' && c <= 'F') 
return c - 'A' + 10;
if (c >= 'a' && c <= 'f') 
return c - 'a' + 10;
else
return c = 0; // Not in hexadecimal
}
// Returns the integer value of a hexadecimal string
int hextoint(char *hex, int len)
{
 if (len == 0) 
return 0;
 return (hextoint(hex,len -1)*16 + xtod(hex[len -1])); 
}
void Printpacket(){
printf("\n............Packet Information starts here.........\n\n");
printf("Index : %d Time : %f Source : %s Destination : %s Protocol : %s Info : %s \nEncapsulation : %s\nLess Relevant : %s",count_printed,packet_struct[count_printed].arrival_time,packet_struct[count_printed].source,packet_struct[count_printed].destination,packet_struct[count_printed].protocol,packet_struct[count_printed].relevant,packet_struct[count_printed].protocol_hierarchy,packet_struct[count_printed].less_relevant);
printf("\n............Packet Information ends here.........\n\n");
}
void Printhexdump(unsigned char *packet,int len){
int t = 0;
while(t < len) {
sprintf(packet_struct[count_printed].hex_dump,"%s%02x",packet_struct[count_printed].hex_dump,packet[t]);
t++;
}
}
void PrintPacketInformation_UDP(unsigned char *packet, int len)
{
int IP_header_length;
int s_port;
int d_port;
// Temporary Storage
int size = 100;
char temp[5];
char temp1[size]; 
char temp2[size];
sprintf(temp,"%02x",packet[14]);
IP_header_length = xtod(temp[1]);
IP_header_length = 4*IP_header_length;
// Relevant to UDP
bzero(temp,5);
sprintf(temp,"%02x%02x",packet[14 + IP_header_length],packet[35 + IP_header_length]);
s_port = hextoint(temp,4);
sprintf(packet_struct[count_printed].relevant,"Source Port : %d",s_port);
bzero(temp,5);

sprintf(temp,"%02x%02x",packet[16 + IP_header_length],packet[17 + IP_header_length]);
d_port = hextoint(temp,4);
//Checking for some commonly used dest_ports
if (d_port == 2008) {
sprintf(packet_struct[count_printed].relevant,"%s Destination Port : terminaldb",packet_struct[count_printed].relevant);
return;
}
// Simple Service Discovery Protocol - 
else if (d_port == 1900){
sprintf(packet_struct[count_printed].protocol,"SSDP");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:SSDP",packet_struct[count_printed].protocol_hierarchy);
if (s_port == 1900)
sprintf(packet_struct[count_printed].relevant,"NOTIFY * HTTP/1.1");
else
sprintf(packet_struct[count_printed].relevant,"%s M-SEARCH * HTTP/1.1",packet_struct[count_printed].relevant);
return;
}
else if (d_port == 10007){
sprintf(packet_struct[count_printed].relevant,"%s Destination Port : mvs-capacity",packet_struct[count_printed].relevant);
return;
}
else if (d_port == 17500 && s_port == 17500){
sprintf(packet_struct[count_printed].relevant,"DropBox LAN Sync Discovery Protocol");
return;
}
//Simply print the port, if the above checks fail

else {
sprintf(packet_struct[count_printed].relevant,"%s Destination Port : %d",packet_struct[count_printed].relevant,d_port);
return;
}
}
void PrintPacketInformation_UDP_IPv6(unsigned char *packet,int len)
{
int s_port;
int d_port;
char temp[5];
bzero(temp,5);
sprintf(temp,"%02x%02x",packet[54],packet[55]);
s_port = hextoint(temp,4);
sprintf(packet_struct[count_printed].relevant,"Source Port : %d",s_port);
bzero(temp,5);
sprintf(temp,"%02x%02x",packet[56],packet[57]);
d_port = hextoint(temp,4);
// Checking for some commonly used dest_ports
/* The WS-Discovery protocol uses the UDP port 3702. The multicast 
address used is 239.255.255.250 on IPV4 networks and 
 [FF02::C] on IPV6 networks. The WS-Discovery protocol uses SOAP and 
UDP (User Datagram Protocol) multicast to enable 
 services to be discovered by a client */
 
if (d_port == 3702){
sprintf(packet_struct[count_printed].relevant,"%s Destination Port : ws-discovery",packet_struct[count_printed].relevant);
return;
 }
if (d_port == 2008) {
sprintf(packet_struct[count_printed].relevant,"%s Destination Port : terminaldb",packet_struct[count_printed].relevant);

return;
}
// Simple Service Discovery Protocol - 
else if (d_port == 1900){
sprintf(packet_struct[count_printed].protocol,"SSDP");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:SSDP",packet_struct[count_printed].protocol_hierarchy);
if (s_port == 1900)
sprintf(packet_struct[count_printed].relevant,"NOTIFY * HTTP/1.1");
else
sprintf(packet_struct[count_printed].relevant,"%s M-SEARCH * HTTP/1.1",packet_struct[count_printed].relevant);
return;
}
else if (d_port == 10007){
sprintf(packet_struct[count_printed].relevant,"%s Destination Port : mvs-capacity",packet_struct[count_printed].relevant);
return;
}
else if (d_port == 17500 && s_port == 17500){
sprintf(packet_struct[count_printed].relevant,"DropBox LAN Sync Discovery Protocol");
return;
}
//Simply print the port, if the above checks fail
else {
sprintf(packet_struct[count_printed].relevant,"%s Destination Port : %d",packet_struct[count_printed].relevant,d_port);
return;
}
}

void PrintPacketInformation_TCP(unsigned char *packet, int len){
char temp[5];
int window_size;
int IP_header_length;
int s_port;
int d_port;
int time_to_live;
//Header length field - The check is necessary because it is not necessary that the length is always 20 bytes
sprintf(temp,"%02x",packet[14]);
IP_header_length = xtod(temp[1]);
IP_header_length = 4*IP_header_length;
bzero(temp,5);
sprintf(temp,"%02x%02x",packet[14 + IP_header_length],packet[15 + IP_header_length]);
s_port = hextoint(temp,4);
bzero(temp,5);
sprintf(temp,"%02x%02x",packet[16 + IP_header_length],packet[17 + IP_header_length]);
d_port = hextoint(temp,4);
//Check for some well known protocols
//Check for FTP
if (s_port == 21){
sprintf(packet_struct[count_printed].protocol,"FTP");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:FTP",packet_struct[count_printed].protocol_hierarchy);
}
//Check for Echo
else if (s_port == 7){
sprintf(packet_struct[count_printed].protocol,"Echo");

sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:Echo",packet_struct[count_printed].protocol_hierarchy);
}
//Check for SSH
else if (s_port == 22){
sprintf(packet_struct[count_printed].protocol,"SSH");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:SSH",packet_struct[count_printed].protocol_hierarchy);
}
//Check for Telnet
else if (s_port == 23){
sprintf(packet_struct[count_printed].protocol,"Telnet");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:Telnet",packet_struct[count_printed].protocol_hierarchy);
}
//Check for imap
else if (s_port == 143){
sprintf(packet_struct[count_printed].protocol,"IMAP");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:IMAP",packet_struct[count_printed].protocol_hierarchy);
}
//Check for http
else if (s_port == 80){
sprintf(packet_struct[count_printed].protocol,"HTTP");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:HTTP",packet_struct[count_printed].protocol_hierarchy);
}

//Check for pop3
else if (s_port == 110){
sprintf(packet_struct[count_printed].protocol,"Pop3");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:Pop3",packet_struct[count_printed].protocol_hierarchy);
}
//Check for https
else if (s_port == 443){
sprintf(packet_struct[count_printed].protocol,"HTTPS");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:HTTPS",packet_struct[count_printed].protocol_hierarchy);
}
// None of the above protocols
else{
sprintf(packet_struct[count_printed].less_relevant,"%sSource Port : %d Destination Port : %d\n",packet_struct[count_printed].less_relevant,s_port,d_port);
}
bzero(temp,5);
sprintf(temp,"%02x",packet[22]);
time_to_live = hextoint(temp,2);
bzero(temp,5);
sprintf(temp,"%02x%02x",packet[28 + IP_header_length],packet[29 + IP_header_length]);
window_size = hextoint(temp,4);
sprintf(packet_struct[count_printed].relevant,"Time to live %d, Window size: %d",time_to_live,window_size);
}
void PrintPacketInformation_TCP_IPv6(unsigned char *packet, int len){

char temp[5];
int window_size;
int s_port;
int d_port;
int time_to_live;
bzero(temp,5);
sprintf(temp,"%02x%02x",packet[54],packet[55]);
s_port = hextoint(temp,4);
bzero(temp,5);
sprintf(temp,"%02x%02x",packet[56],packet[57]);
d_port = hextoint(temp,4);
//Check for some well known protocols
//Check for FTP
if (s_port == 21){
sprintf(packet_struct[count_printed].protocol,"FTP");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:FTP",packet_struct[count_printed].protocol_hierarchy);
}
//Check for Echo
else if (s_port == 7){
sprintf(packet_struct[count_printed].protocol,"Echo");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:Echo",packet_struct[count_printed].protocol_hierarchy);
}
//Check for SSH
else if (s_port == 22){
sprintf(packet_struct[count_printed].protocol,"SSH");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:SSH",packet_struct[count_printed].protocol_hierarchy);
}

//Check for Telnet
else if (s_port == 23){
sprintf(packet_struct[count_printed].protocol,"Telnet");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:Telnet",packet_struct[count_printed].protocol_hierarchy);
}
//Check for imap
else if (s_port == 143){
sprintf(packet_struct[count_printed].protocol,"IMAP");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:IMAP",packet_struct[count_printed].protocol_hierarchy);
}
//Check for http
else if (s_port == 80){
sprintf(packet_struct[count_printed].protocol,"HTTP");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:HTTP",packet_struct[count_printed].protocol_hierarchy);
}
//Check for pop3
else if (s_port == 110){
sprintf(packet_struct[count_printed].protocol,"Pop3");
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:Pop3",packet_struct[count_printed].protocol_hierarchy);
}
//Check for https
else if (s_port == 443){
sprintf(packet_struct[count_printed].protocol,"HTTPS");

sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:HTTPS",packet_struct[count_printed].protocol_hierarchy);
}
// None of the above protocols
else{
sprintf(packet_struct[count_printed].less_relevant,"%sSource Port : %d Destination Port : %d",packet_struct[count_printed].less_relevant,s_port,d_port);
}
bzero(temp,5);
sprintf(temp,"%02x",packet[42]);
time_to_live = hextoint(temp,2);
bzero(temp,5);
sprintf(temp,"%02x%02x",packet[68],packet[69]);
window_size = hextoint(temp,4);
sprintf(packet_struct[count_printed].relevant,"Time to live %d, Window size: %d",time_to_live,window_size);
}
void PrintPacketInformation_ICMP(unsigned char *packet, int len){
char temp[5];
int IP_header_length;
int type; // Type of ICMP request
// Not so relevant 
bzero(temp,5);
sprintf(temp,"%02x",packet[14]);
IP_header_length = xtod(temp[1]);
IP_header_length = 4*IP_header_length;
bzero(temp,5);
sprintf(temp,"%02x",packet[14 + IP_header_length]);

type = hextoint(temp,2);
if (type == 0) {
sprintf(packet_struct[count_printed].relevant,"Echo reply");
return;
}
if (type == 8) {
sprintf(packet_struct[count_printed].relevant,"Echo request");
return;
}
if (type == 9) {
sprintf(packet_struct[count_printed].relevant,"Routerdiscovery/selection/solicitation");
return;
}
else {
sprintf(packet_struct[count_printed].relevant,"ICMP packet of type %d\n",type);
return;
}
}
void PrintPacketInformation_ICMP_IPv6(unsigned char *packet, int len){
char temp[5];
int type; // Type of ICMP request
// Not so relevant 
bzero(temp,5);
sprintf(temp,"%02x",packet[54]);
type = hextoint(temp,2);
if (type == 128) {
sprintf(packet_struct[count_printed].relevant,"Echo Request");
return;
}

if (type == 129) {
sprintf(packet_struct[count_printed].relevant,"Echo Reply");
return;
}
if (type == 133) {
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:NDP",packet_struct[count_printed].protocol_hierarchy);
sprintf(packet_struct[count_printed].protocol,"NDP");
sprintf(packet_struct[count_printed].relevant,"Router Soclicitation");
return;
}
if (type == 134) {
sprintf(packet_struct[count_printed].relevant,"Router Advertisement");
return;
}
if (type == 135) {
sprintf(packet_struct[count_printed].relevant,"Neighbour solicitation");
return;
}
else {
sprintf(packet_struct[count_printed].relevant,"ICMPv6 packet of type %d\n",type);
return;
}
}
int PrintPacketInformation_ARP(unsigned char *packet, int len){
char opcode[3];
// Temporary Storage
int size = 100;
char temp1[size]; 

char temp2[size];
sprintf(opcode,"%02x%02x",packet[20],packet[21]);
if (strcmp(opcode,"0001")==0){
// ARP Request
// Destination MAC
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Destination MAC address: ");
sprintf(temp2,"%02x:%02x:%02x:%02x:%02x:%02x", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
if ((strcmp(destination_MAC,"") != 0) && (strcmp(destination_MAC,temp2) != 0))
return 0;
sprintf(packet_struct[count_printed].less_relevant,"%s%s\n",temp1,temp2);
// Source MAC
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Source MAC address: ");
sprintf(temp2,"%02x:%02x:%02x:%02x:%02x:%02x", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
if ((strcmp(source_MAC,"") != 0) && (strcmp(source_MAC,temp2) != 0))
return 0;
sprintf(temp1,"%s%s\n",temp1,temp2);
strcat(packet_struct[count_printed].less_relevant,temp1);
//Source
sprintf(packet_struct[count_printed].source,"%s",temp2);
// Source IP-compare
bzero(temp2,size);
sprintf(temp2,"%d.%d.%d.%d",packet[28],packet[29],packet[30],packet[31]);
if (strcmp(temp2,source_ip)!= 0)
return 0;
// Destination IP -Compare

sprintf(packet_struct[count_printed].destination,"%d.%d.%d.%d",packet[38],packet[39],packet[40],packet[41]);
if (strcmp(packet_struct[count_printed].destination,destination_ip) != 0){
return 0;
}
// Destination
sprintf(packet_struct[count_printed].destination,"Broadcast");
// Relevant Information
sprintf(packet_struct[count_printed].relevant,"Who has %d.%d.%d. %d ? Tell %d.%d.%d.%d",packet[38],packet[39],packet[40],packet[41],packet[28],packet[29],packet[30],packet[31]);
}
if (strcmp(opcode,"0002")==0){
// ARP reply
// Destination MAC
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Destination MAC address: ");
sprintf(temp2,"%02x:%02x:%02x:%02x:%02x:%02x", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
if ((strcmp(destination_MAC,"") != 0) && (strcmp(destination_MAC,temp2) != 0))
return 0;
sprintf(packet_struct[count_printed].less_relevant,"%s%s\n",temp1,temp2);
// Destination
sprintf(packet_struct[count_printed].destination,"%s",temp2);
// Source MAC
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Source MAC address: ");
sprintf(temp2,"%02x:%02x:%02x:%02x:%02x:%02x", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
if ((strcmp(source_MAC,"") != 0) && (strcmp(source_MAC,temp2) != 0))

return 0;
sprintf(temp1,"%s%s\n",temp1,temp2);
strcat(packet_struct[count_printed].less_relevant,temp1);
// Source 
sprintf(packet_struct[count_printed].source,"%s",temp2);
// Relevant Information
sprintf(packet_struct[count_printed].relevant,"%d.%d.%d.%d has MAC address %02x:%02x:%02x:%02x:%02x:%02x\n",packet[28],packet[29],packet[30],packet[31],packet[22],packet[23],packet[24],packet[25],packet[26],packet[27]);
// Source IP-compare
bzero(temp2,size);
sprintf(temp2,"%d.%d.%d.%d",packet[28],packet[29],packet[30],packet[31]);
if (strcmp(temp2,source_ip)!= 0)
return 0;
// Destination IP-comapare
bzero(temp2,size);
sprintf(temp2,"%d.%d.%d.%d",packet[38],packet[39],packet[40],packet[41]);
if (strcmp(temp2,destination_ip)!= 0)
return 0;
}
return 1;
}
int PrintPacketInformation(unsigned char *packet, int len)
{
sprintf(packet_struct[count_printed].protocol_hierarchy,"Ethernet");
sprintf(packet_struct[count_printed].protocol,"Ethernet");
// Stores the Ether type field of the Ethernet packet
char eth_type[4];
// Stores the Protocol field of the IPv4 packet
char IP_type[2];

// Stores the "Next Header" field of the IPv6 packet
char IPv6_type[2];
// Temporary Storage
int size = 100;
char temp1[size]; 
char temp2[size];
int t = 0;
sprintf(eth_type, "%02x%02x",packet[12],packet[13]);
// IPv4 - Ethertype field = 0x0800
if (strcmp(eth_type,"0800") == 0 && ((strcmp(protocol,"ipv4") == 0) || (strcmp(protocol,"ipv4|udp") == 0) || (strcmp(protocol,"ipv4|tcp") == 0) || (strcmp(protocol,"ipv4|icmp") == 0) || (strcmp(protocol,"all") == 0))){
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:IPv4",packet_struct[count_printed].protocol_hierarchy);
sprintf(packet_struct[count_printed].protocol,"IPv4");
// Destination MAC
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Destination MAC address: ");
sprintf(temp2,"%02x:%02x:%02x:%02x:%02x:%02x", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
if ((strcmp(destination_MAC,"") != 0) && (strcmp(destination_MAC,temp2) != 0))
return 0;
sprintf(temp1,"%s%s\n",temp1,temp2);
strcat(packet_struct[count_printed].less_relevant,temp1);
// Source MAC
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Source MAC address: ");
sprintf(temp2,"%02x:%02x:%02x:%02x:%02x:%02x", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

if ((strcmp(source_MAC,"") != 0) && (strcmp(source_MAC,temp2) != 0))
return 0;
sprintf(temp1,"%s%s\n",temp1,temp2);
strcat(packet_struct[count_printed].less_relevant,temp1);
// Source IP
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Source IP address: ");
sprintf(temp2,"%d.%d.%d.%d", packet[26], packet[27], packet[28],packet[29]);
if ((strcmp(source_ip,"") != 0) && (strcmp(source_ip,temp2) != 0))
return 0;
sprintf(temp1,"%s%s\n",temp1,temp2);
strcat(packet_struct[count_printed].less_relevant,temp1);
// Source
sprintf(packet_struct[count_printed].source,"%s",temp2);`
// Destination IP
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Destination IP address: ");
sprintf(temp2,"%d.%d.%d.%d", packet[30], packet[31], packet[32], packet[33]);
if ((strcmp(destination_ip,"") != 0) && (strcmp(destination_ip,temp2) != 0))
return 0;
sprintf(temp1,"%s%s\n",temp1,temp2);
strcat(packet_struct[count_printed].less_relevant,temp1);
// Destination
sprintf(packet_struct[count_printed].destination,"%s",temp2);
//Find out the type of protocol
sprintf(IP_type,"%02x",packet[23]);
if ((strcmp(IP_type,"06") == 0) && ((strcmp(protocol,"all") == 0) || (strcmp(protocol,"ipv4") == 0) || (strcmp(protocol,"ipv4|tcp") == 0))){
// TCP packet

sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:TCP",packet_struct[count_printed].protocol_hierarchy);
sprintf(packet_struct[count_printed].protocol,"TCP");
PrintPacketInformation_TCP(packet, len);
return 1;
}
if ((strcmp(IP_type,"11") == 0) && ((strcmp(protocol,"all") == 0) || (strcmp(protocol,"ipv4") == 0) || (strcmp(protocol,"ipv4|udp") == 0))) {
// UDP packet
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:UDP",packet_struct[count_printed].protocol_hierarchy);
sprintf(packet_struct[count_printed].protocol,"UDP");
PrintPacketInformation_UDP(packet, len);
return 1;
}
if ((strcmp(IP_type,"01") == 0) && ((strcmp(protocol,"all") == 0) || (strcmp(protocol,"ipv4") == 0) || (strcmp(protocol,"ipv4|icmp") == 0))){
// ICMP packet
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:ICMP",packet_struct[count_printed].protocol_hierarchy);
sprintf(packet_struct[count_printed].protocol,"ICMP");
PrintPacketInformation_ICMP(packet, len);
return 1;
}
}
// ARP - Ethertype field = 0x0806
else if ((strcmp(eth_type,"0806") == 0) && ((strcmp(protocol,"arp") == 0) ||(strcmp(protocol,"all") == 0))){
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:ARP",packet_struct[count_printed].protocol_hierarchy);

sprintf(packet_struct[count_printed].protocol,"ARP");
return PrintPacketInformation_ARP(packet,len);
}
//IPv6 - Ethertype field = 0x86dd
else if ((strcmp(eth_type,"86dd") == 0) && ((strcmp(protocol,"ipv6") == 0) || (strcmp(protocol,"ipv6|udp") == 0) || (strcmp(protocol,"ipv6|tcp") == 0) || (strcmp(protocol,"ipv6|icmp") == 0) || (strcmp(protocol,"all") == 0))){
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:IPv6",packet_struct[count_printed].protocol_hierarchy);
sprintf(packet_struct[count_printed].protocol,"IPv6");
// Destination MAC
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Destination MAC address: ");
sprintf(temp2,"%02x:%02x:%02x:%02x:%02x:%02x", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
if ((strcmp(destination_MAC,"") != 0) && (strcmp(destination_MAC,temp2) != 0))
return 0;
sprintf(packet_struct[count_printed].less_relevant,"%s%s\n",temp1,temp2);
// Source MAC
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Source MAC address: ");
sprintf(temp2,"%02x:%02x:%02x:%02x:%02x:%02x", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
if ((strcmp(source_MAC,"") != 0) && (strcmp(source_MAC,temp2) != 0))
return 0;
sprintf(temp1,"%s%s\n",temp1,temp2);
strcat(packet_struct[count_printed].less_relevant,temp1);

// Source IPv6
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Source IPv6 address: ");
sprintf(temp2,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", packet[22], packet[23], packet[24], packet[25], packet[26], packet[27], packet[28], packet[29], packet[30], packet[31],packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);
if ((strcmp(source_ip,"") != 0) && (strcmp(source_ip,temp2) != 0))
return 0;
sprintf(temp1,"%s%s\n",temp1,temp2);
strcat(packet_struct[count_printed].less_relevant,temp1);
// Source - field of packe
sprintf(packet_struct[count_printed].source,"%s",temp2);
// Destination IPv6
bzero(temp1,size);
bzero(temp2,size);
sprintf(temp1,"Destination IPv6 address: ");
sprintf(temp2,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", packet[38], packet[39], packet[40], packet[41], packet[42], packet[43], packet[44], packet[45], packet[46], packet[47],packet[48], packet[49], packet[50], packet[51], packet[52], packet[53]);
if ((strcmp(destination_ip,"") != 0) && (strcmp(destination_ip,temp2) != 0))
return 0;
sprintf(packet_struct[count_printed].destination,"%s",temp2);
sprintf(temp1,"%s%s\n",temp1,temp2);
strcat(packet_struct[count_printed].less_relevant,temp1);
// Destination
sprintf(packet_struct[count_printed].destination,"%s",temp2);
//Next Header field
sprintf(IPv6_type,"%02x",packet[20]);
// Depending on the Next Header Field
if ((strcmp(IPv6_type,"11") == 0) && ((strcmp(protocol,"all") == 0) || (strcmp(protocol,"ipv6") == 0) || (strcmp(protocol,"ipv6|udp") == 0))){
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:UDP",packet_struct[count_printed].protocol_hierarchy);
sprintf(packet_struct[count_printed].protocol,"UDP");
PrintPacketInformation_UDP_IPv6(packet,len);
return 1;
}
if ((strcmp(IPv6_type,"06") == 0) && ((strcmp(protocol,"all") == 0) ||
(strcmp(protocol,"ipv6") == 0) || (strcmp(protocol,"ipv6|tcp") == 0))){
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:TCP",packet_struct[count_printed].protocol_hierarchy);
sprintf(packet_struct[count_printed].protocol,"TCP");
PrintPacketInformation_TCP_IPv6(packet,len);
return 1;
}
if ((strcmp(IPv6_type,"3a") == 0) && ((strcmp(protocol,"all") == 0) ||
(strcmp(protocol,"ipv6") == 0) || (strcmp(protocol,"ipv6|icmp") == 0))){
sprintf(packet_struct[count_printed].protocol_hierarchy,"%s:ICMPv6",packet_struct[count_printed].protocol_hierarchy);
sprintf(packet_struct[count_printed].protocol,"ICMPv6");
PrintPacketInformation_ICMP_IPv6(packet,len);
return 1;
}
}
// If the packet is of none of the above types then fill the entries with "Unknown"
else{
sprintf(packet_struct[count_printed].source,"Unknown");
sprintf(packet_struct[count_printed].destination,"Unknown");
sprintf(packet_struct[count_printed].protocol,"Unknown");

sprintf(packet_struct[count_printed].relevant,"Packet of unknown type");
sprintf(packet_struct[count_printed].less_relevant,"Packet of unknown type, not identified by our software");
return 1;
}
if (strcmp(protocol,"all") == 0)
return 1;
return 0;
}
