#include <pcap/pcap.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <map>
#include <set>
#include <string>
#include <algorithm>

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);            // callback function for loop
u_int16_t handleEthernet(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet); // function for handling ethernet header
void handleIP(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);            // function for handling ip header
void handleARP(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);           // function for handling arp header
void dieWithError(const char *errMsg);                                                             // generic error function

struct my_ip // structure for ip header
{
    u_int8_t ip_vhl;
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

struct my_arp // structure for arp header
{
    uint16_t htype;        // Format of hardware address
    uint16_t ptype;        // Format of protocol address
    uint8_t hlen;          // Length of hardware address
    uint8_t plen;          // Length of protocol address
    uint16_t op;           // ARP opcode (command)
    uint8_t sha[ETH_ALEN]; // Sender hardware address
    uint32_t spa;          // Sender IP address
    uint8_t tha[ETH_ALEN]; // Target hardware address
    uint32_t tpa;          // Target IP address
};

struct my_udp // structure for udp header
{
    u_int16_t uh_sport;
    u_int16_t uh_dport;
    u_int16_t uh_ulen;
    u_int16_t uh_sum;
};

int count = 0;
long double totalBytes = 0.0;
long double minBytes = 0.0;
long double maxBytes = 0.0;

struct timeval prevTv;

std::map<std::string, int> uEthSenders;   // map for ethernet seders
std::map<std::string, int> uEthReceivers; // map for ethernet receivers
std::map<std::string, int> uIPSenders;    // map for ip senders
std::map<std::string, int> uIPReceivers;  // map for ip receivers

std::map<std::string, std::string> arpMachines; // map for arp participants

std::set<uint16_t> uUDPSourcePorts; // vector for UDP source ports
std::set<uint16_t> uUDPDestPorts;   // vector for UDP destination ports

int main(int argc, char *argv[])
{
    if (argc != 2) // command line args not equal to 2
    {
        dieWithError("Error: Incorrect number of arguments!");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descriptor = pcap_open_offline(argv[1], errbuf); // open the pcap file
    int datalink = pcap_datalink(descriptor);                // get the datalink descriptor

    if (datalink != DLT_EN10MB)
    {
        dieWithError("Error: Ethernet not detected!");
    }

    pcap_loop(descriptor, -1, callback, NULL); // run the pcap loop function
    pcap_close(descriptor);

    // print out lists and statistical information
    printf("Total Number of Packets: %d\n", count);

    printf("\n");
    printf("Unique Senders (Ethernet):\n");
    std::for_each(uEthSenders.begin(), uEthSenders.end(), [](const std::pair<std::string, int> &p)
                  { printf("    %s - %d packet(s)\n", p.first.c_str(), p.second); });

    printf("\n");
    printf("Unique Receivers (Ethernet):\n");
    std::for_each(uEthReceivers.begin(), uEthReceivers.end(), [](const std::pair<std::string, int> &p)
                  { printf("    %s - %d packet(s)\n", p.first.c_str(), p.second); });

    printf("\n");
    printf("Unique Senders (IP):\n");
    std::for_each(uIPSenders.begin(), uIPSenders.end(), [](const std::pair<std::string, int> &p)
                  { printf("    %s - %d packet(s)\n", p.first.c_str(), p.second); });

    printf("\n");
    printf("Unique Receivers (IP):\n");
    std::for_each(uIPReceivers.begin(), uIPReceivers.end(), [](const std::pair<std::string, int> &p)
                  { printf("    %s - %d packet(s)\n", p.first.c_str(), p.second); });

    if (arpMachines.size() > 0) // if map of arp machines is not empty
    {
        printf("\n");
        printf("ARP Machines:\n");
        std::for_each(arpMachines.begin(), arpMachines.end(), [](const std::pair<std::string, std::string> &p)
                      { printf("    IP: %s\t MAC: %s\n", p.first.c_str(), p.second.c_str()); });
    }

    if (uUDPSourcePorts.size() > 0) // if udp source ports are not empty
    {
        printf("\n");
        printf("UDP Source Ports:\n");
        for (auto port : uUDPSourcePorts)
        {
            printf("    %u\n", port);
        }
    }

    if (uUDPDestPorts.size() > 0) // if udp destination ports are not empty
    {
        printf("\n");
        printf("UDP Destination Ports:\n");
        for (auto port : uUDPDestPorts)
        {
            printf("    %u\n", port);
        }
    }

    printf("\n"); // print statistical information
    printf("Average Packet Size: %Lf\n", (totalBytes / count));
    printf("Minimum Packet Size: %d\n", (int)minBytes);
    printf("Maximum Packet Size: %d\n", (int)maxBytes);

    return 0;
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) // callback function in loop
{
    u_int length = pkthdr->len;
    count++; // increment packet count
    printf("Packet %d:\n", count);
    printf("    Packet Size: %d\n", length);

    struct timeval tv = pkthdr->ts; // get the time from the header
    time_t nowTime;
    struct tm *nowTm;
    char tmBuff[64], buff[64];

    nowTime = tv.tv_sec; // convert the time to the right format
    nowTm = localtime(&nowTime);
    strftime(tmBuff, sizeof tmBuff, "%Y-%m-%d %H:%M:%S", nowTm);
    printf("    Start Date and Time: %s\n", tmBuff);

    if (prevTv.tv_sec != 0 && prevTv.tv_usec != 0) // print the start date and time of capture
    {
        struct timeval duration;
        timersub(&tv, &prevTv, &duration);
        printf("    Duration of Packet Capture: %ld.%06ld s\n", duration.tv_sec, duration.tv_usec);
    }
    else
    {
        printf("    Duration of Packet Capture: %ld.%06ld s\n", prevTv.tv_sec, prevTv.tv_usec);
    }

    double packetLength = length; // get the minimum and maximum packet lengths
    if (packetLength > maxBytes)
    {
        maxBytes = packetLength;
    }
    if ((packetLength < minBytes) || (minBytes == 0))
    {
        minBytes = packetLength;
    }
    totalBytes += packetLength; // increment the total size for average calculation

    prevTv = tv;
    handleEthernet(useless, pkthdr, packet); // call handle ethernet function
    printf("\n");
}

u_int16_t handleEthernet(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) // handle ethernet header
{
    struct ether_header *eptr;
    eptr = (struct ether_header *)packet;

    printf("    Ethernet: ");
    if (ntohs(eptr->ether_type) == ETHERTYPE_IP) // check the ethernet header type
    {
        printf("(IP)\n");
    }
    else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
    {
        printf("(ARP)\n");
    }
    else
    {
        printf("(?)\n");
    }

    std::string etherSource = ether_ntoa((const struct ether_addr *)&eptr->ether_shost); // get ethernet source
    std::string etherDest = ether_ntoa((const struct ether_addr *)&eptr->ether_dhost);   // get ethernet destination

    printf("        Source: %s\n", etherSource.c_str());
    printf("        Destination: %s\n", etherDest.c_str());

    // add ethernet source and destination to map
    if (uEthSenders.count(etherSource) > 0)
    {
        uEthSenders[etherSource] = uEthSenders[etherSource] + 1;
    }
    else
    {
        uEthSenders.insert(std::pair<std::string, int>(etherSource, 1));
    }

    if (uEthReceivers.count(etherDest) > 0)
    {
        uEthReceivers[etherDest] = uEthReceivers[etherDest] + 1;
    }
    else
    {
        uEthReceivers.insert(std::pair<std::string, int>(etherDest, 1));
    }

    if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
    {
        handleIP(useless, pkthdr, packet); // handle ip header
    }
    else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
    {
        handleARP(useless, pkthdr, packet); // handle arp header
    }

    return eptr->ether_type;
}

void handleIP(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) // handle ip header
{
    const struct my_ip *ip; // initialize values for ip header
    u_int length = pkthdr->len;
    u_int hlen, off, version, protocol;
    int i, len;

    ip = (struct my_ip *)(packet + sizeof(struct ether_header)); // get pointer in correct position
    length -= sizeof(struct ether_header);

    if (length < sizeof(ip)) // length is invalid
    {
        dieWithError("Error: Not a valid length!");
    }

    len = ntohs(ip->ip_len); // get length of ip header
    hlen = IP_HL(ip);        // get the hlen of ip header
    version = IP_V(ip);      // get the version of ip header (IPv4)

    protocol = ip->ip_p;

    if (version != 4) // make sure version is IPv4
    {
        dieWithError("Error: Unknown version!");
    }

    if (hlen < 5) // hlen is invalid
    {
        dieWithError("Error: Bad header length!");
    }

    if (length < len) // bytes are not present in header
    {
        dieWithError("Error: Bytes missing!");
    }

    std::string ipSource = inet_ntoa(ip->ip_src);
    std::string ipDest = inet_ntoa(ip->ip_dst);

    off = ntohs(ip->ip_off);
    if ((off & 0x1fff) == 0) // print ip header information
    {
        printf("    Internet Protocol:\n");
        printf("        Source: %s\n", ipSource.c_str());
        printf("        Destination: %s\n", ipDest.c_str());
        printf("        Header Length: %d, Version: %d, Length: %d, Offset: %d\n", hlen, version, len, off);
    }

    if (protocol == IPPROTO_UDP) // handle udp
    {
        const struct my_udp *udp;                                                      // initialize values for udp header
        udp = (struct my_udp *)(packet + sizeof(struct ether_header) + sizeof(my_ip)); // get pointer in correct position
        uint16_t sourcePort = ntohs(udp->uh_sport);                                    // get the udp source port
        uint16_t destPort = ntohs(udp->uh_dport);                                      // get the udp destination port

        // insert the ports into respective lists
        uUDPSourcePorts.insert(sourcePort);
        uUDPDestPorts.insert(destPort);
        printf("        User Datagram Protocol (UDP):\n");
        printf("            Source Port: %d, Destination Port: %d\n", sourcePort, destPort);
    }

    if (uIPSenders.count(ipSource) > 0)
    {
        uIPSenders[ipSource] = uIPSenders[ipSource] + 1;
    }
    else
    {
        uIPSenders.insert(std::pair<std::string, int>(ipSource, 1));
    }

    if (uIPReceivers.count(ipDest) > 0)
    {
        uIPReceivers[ipDest] = uIPReceivers[ipDest] + 1;
    }
    else
    {
        uIPReceivers.insert(std::pair<std::string, int>(ipDest, 1));
    }
}

void handleARP(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    const struct my_arp *arp; // initialize values for arp header
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int i, len;

    arp = (struct my_arp *)(packet + sizeof(struct ether_header)); // get pointer in correct position
    length -= sizeof(struct ether_header);

    uint16_t opcode = ntohs(arp->op); // get the arp op code for request or reply
    std::string opcodeString;

    if (opcode == 1)
    {
        opcodeString = "Request";
    }
    else if (opcode == 2)
    {
        opcodeString = "Reply";
    }
    else
    {
        opcodeString = "Other Opcode";
    }

    std::string ipSource = inet_ntoa(*(struct in_addr *)&arp->spa); // get the ip source for arp
    std::string ipDest = inet_ntoa(*(struct in_addr *)&arp->tpa);   // get the ip destination for arp

    std::string macSource, macDest;
    if (opcode == 2) // no mac address if arp reply
    {
        macSource = "N/A";
        macDest = "N/A";
    }
    else
    {
        macSource = ether_ntoa((struct ether_addr *)&arp->sha); // get the mac source for arp
        macDest = ether_ntoa((struct ether_addr *)&arp->tha);   // get the mac destination for arp
    }

    // add addresses to list of machines participating in arp
    if (arpMachines.count(ipSource) < 1)
    {
        arpMachines.insert(std::pair<std::string, std::string>(ipSource, macSource));
    }
    if (arpMachines.count(ipDest) < 1)
    {
        arpMachines.insert(std::pair<std::string, std::string>(ipDest, macDest));
    }

    printf("    Address Resolution Protocol:\n"); // print arp information
    printf("        Source: %s (IP), %s (MAC)\n", ipSource.c_str(), macSource.c_str());
    printf("        Destination: %s (IP), %s (MAC)\n", ipDest.c_str(), macDest.c_str());
    printf("        Opcode: %u (%s)\n", opcode, opcodeString.c_str());

    if (uIPSenders.count(ipSource) > 0)
    {
        uIPSenders[ipSource] = uIPSenders[ipSource] + 1;
    }
    else
    {
        uIPSenders.insert(std::pair<std::string, int>(ipSource, 1));
    }

    if (uIPReceivers.count(ipDest) > 0)
    {
        uIPReceivers[ipDest] = uIPReceivers[ipDest] + 1;
    }
    else
    {
        uIPReceivers.insert(std::pair<std::string, int>(ipDest, 1));
    }
}

// error logging function
void dieWithError(const char *errMsg)
{
    printf("%s\n", errMsg);
    printf("\n");
    exit(1);
}
