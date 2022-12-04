//
// Created by Phil Romig on 11/13/18.
//

#include "packetstats.h"

// ****************************************************************************
// * pk_processor()
// *  All of the work done by the program will be done here (or at least it
// *  it will originate here). The function will be called once for every
// *  packet in the savefile.
// ****************************************************************************
void pk_processor(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    resultsC* results = (resultsC*)user;
    results->incrementTotalPacketCount();
    DEBUG << "Processing packet #" << results->packetCount() << ENDL;
    char s[256]; memset(s,0,256); memcpy(s,ctime(&(pkthdr->ts.tv_sec)),strlen(ctime(&(pkthdr->ts.tv_sec)))-1);
    TRACE << "\tPacket timestamp is " << s << ENDL;
    TRACE << "\tPacket capture length is " << pkthdr->caplen << ENDL;
    TRACE << "\tPacket physical length is " << pkthdr->len << ENDL;

    // ***********************************************************************
    // * Process the link layer header
    // ***********************************************************************
    //
    // Overlay "struct ether_header" onto the packet
    //
    // Extract the src/dst address, add them to results.
    // (use results->newSrcMac() and results->newDstMac())
    //
    //
    // Is it anything other Than Ethernet II? If so, record it and you are done.
    // length is the physical length of the packet (pkthdr->len)
    // - Record its existance using results->newOtherLink(length)
    //
    // Record it as Ethernet II
    // length is the physical length of the packet (pkthdr->len)
    // - Record its existance using results->newEthernet(length)

      // ***********************************************************************
    // * Process the link layer header
    // ***********************************************************************
    struct ether_header* macHdr = (struct ether_header*)packet;
    u_int64_t sm = 0;
    u_int64_t dm = 0;
    memcpy(&sm,&(macHdr->ether_shost),6);
    memcpy(&dm,&(macHdr->ether_dhost),6);
    results->newSrcMac(sm);
    results->newDstMac(dm);
    TRACE << "\tSource MAC = " << ether_ntoa((const struct ether_addr *)&(macHdr->ether_shost)) << ENDL;
    TRACE << "\tDestination MAC = " << ether_ntoa((const struct ether_addr *)&(macHdr->ether_dhost)) << ENDL;
    TRACE << "\tEther Type = " << ntohs(macHdr->ether_type) << ENDL;
    

    // ***********************************************************************
    // ** If the value in ether_type is less than 1500 then the frame is
    // ** something other than Ethernet. We count tat as "other link" and
    // ** and we are done.
    // ***********************************************************************
    if (ntohs(macHdr->ether_type) <= 1500) { 
      TRACE << "\tPacket is not Ethernet II" << ENDL;
      results->newOtherLink(pkthdr->len);
      return;
    }

    // ***********************************************************************
    // * Now we know the frame is Ethernet II
    // ***********************************************************************
    TRACE << "\tPacket is Ethernet II" << ENDL;
    results->newEthernet(pkthdr->len);

        // ***********************************************************************
    // * Is it ARP?
    // ***********************************************************************
    //
    // Is it an ARP packet? If so, record it in results and you are done.
    // length is the physical length of the packet (pkthdr->len)
    // - Record its existance using results->newARP(length)
    //

    if (ntohs(macHdr->ether_type) == ETHERTYPE_ARP) {
        TRACE << "\tPacket is ARP" << ENDL;
        results->newARP(pkthdr->len);
        return;
    }

    // ***********************************************************************
    // *****************   Process the Network Layer   ************************
    // ***********************************************************************

     // ***********************************************************************
    // * Process the network layer header other than IPv4
    // ***********************************************************************
    //
    // Is it an IPv6 Packet? 
    // length = Total packet length - Ethernet II header length
    // - Record its existance using results->newIPv6(length).
    // 
    
    //
    // Is it anything other than IPv4, record it as other and you are done.
    // length = Total packet length - Ethernet II header length
    // - Record its existance using results->newOtherNetwork())
    //
    
    // ***********************************************************************
    // * First, identify the IPv6 and Other Network using the type field
    // * of the Ethernet frame.
    // ***********************************************************************
    int networkPacketLength = pkthdr->len - 14;
    if (ntohs(macHdr->ether_type) == ETHERTYPE_IPV6) {
        TRACE << "\t\tPacket is IPv6, length is " << networkPacketLength << ENDL;
        results->newIPv6(networkPacketLength);
        return;
    }

    if (ntohs(macHdr->ether_type) != ETHERTYPE_IP) {
        TRACE << "\t\tPacket has an unrecognized ETHERTYPE" << ntohs(macHdr->ether_type)  << ENDL;
        results->newOtherNetwork(networkPacketLength);
        return;
    }

    // ***********************************************************************
    // * Now we know it MUST be an IPv4 Packet
    // ***********************************************************************

     
    // ***********************************************************************
    // * Process IPv4 packets
    // ***********************************************************************
    //
    // If we are here, it must be IPv4, so overlay "struct ip" on the right location.
    // length = Total packet length - Ethernet II header length
    // - Record its existance using results->newIPv4(length)
    // - Record the src/dst addressed in the results class.

    TRACE << "\t\tPacket is IPv4, length is " << networkPacketLength << ENDL;
    results->newIPv4(networkPacketLength);
    struct ip *ipHeader = (struct ip *)(packet+14);

     // ***********************************************************************
    // * Process the Transport Layer
    // ***********************************************************************
    //
    // Is it TCP? Overlay the "struct tcphdr" in the correct location.
    // length = Total packet length - IPv4 header length - Ethernet II header length
    // ** Don't forget that IPv4 headers can be different sizes.
    // - Record its existance using results->newTCP(length)
    // - Record src/dst ports (use results->newSrcTCP or newDstTCP.
    //   note you must store them in host order).
    // - Record SYN and/or FIN flags 
    //   (use results->incrementSynCount(), results->incrementFinCount())

    int transportPacketLength = networkPacketLength - sizeof(ipHeader);
    if(ipHeader->ip_p == IPPROTO_TCP){
      TRACE << "\t\tPacket is TCP, length is " << transportPacketLength << ENDL;
      struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + sizeof(ipHeader));
      results->newTCP(transportPacketLength);
      results->newSrcTCP(ntohs(tcpHeader->source));
      results->newDstTCP(ntohs(tcpHeader->dest));

      if(tcpHeader->th_flags & TH_SYN){
        results->incrementSynCount();
      }
      if(tcpHeader->th_flags & TH_FIN){
        results->incrementFinCount();
      }

      return;
    }
    
    // Is it UDP? Overlay the "struct udphdr" in the correct location.
    // length = Total packet length - IPv4 header length - Ethernet II header length
    // ** Don't forget that IPv4 headers can be different sizes.
    // - Record its existance using results->newUDP(length)
    // - Record src/dst ports (must store them in host order).
    //   (use results->newSrcUDP()( and results->newDstUDP()
    //

    if(ipHeader->ip_p == IPPROTO_UDP){
      TRACE << "\t\tPacket is UDP, length is " << transportPacketLength << ENDL;
      struct udphdr *udpHeader = (struct udphdr *)(packet + 14 + sizeof(udpHeader));
      results->newUDP(transportPacketLength);
      results->newSrcUDP(ntohs(udpHeader->source));
      results->newDstUDP(ntohs(udpHeader->dest));

      return;
    }
    
    //
    // Is it ICMP,
    // length = Total packet length - IPv4 header length - Ethernet II header length
    // ** Don't forget that IPv4 headers can be different sizes.
    // - Record its existance using results->newICMP(length);
    //
    
    if(ipHeader->ip_p == IPPROTO_ICMP){
      TRACE << "\t\tPacket is ICMP, length is " << transportPacketLength << ENDL;
      results->newICMP(transportPacketLength);

      return;
    }

    // 
    // Anything else, record as unknown transport.
    // length = Total packet length - IPv4 header length - Ethernet II header length
    // ** Don't forget that IPv4 headers can be different sizes.
    // - Record its existence using results->newOtherTransport(length)
    //
    TRACE << "\t\tPacket is unkown transport, length is " << transportPacketLength << ENDL;
    results->newOtherTransport(transportPacketLength);

    return;
}
