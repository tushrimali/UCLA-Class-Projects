/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h> 

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("\n--ROUTER RECEIVED A NEW PACKET--\n");
 /* print_hdr_eth(packet);*/

  /* Sanity checks */

  if (len > 1514)
  {
    fprintf(stderr, "Error: EthHeader 1514 check not met");
    return;
  }  

  if (len < sizeof(sr_ethernet_hdr_t)) 
  {
    fprintf(stderr, "Error: Packet size < EthHeader size");
    return;
  } 

  /* IP/ICMP/ARP */
  uint16_t ether_type = ethertype(packet); 

  switch (ether_type)
  {
    /* IP */
    case 0x0800: 
        process_ether_type_ip(sr, packet, len, interface);
        break;

    /* ARP */
    case 0x0806:
        process_ether_type_arp(sr, packet, len, interface);
        break;

    /* Garbage ethernet type */
    default:
        fprintf(stderr, "Error: Garbage ether_type %d", ether_type);
        return;
  }
return;   
}

void process_ether_type_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  /* Create IP header struct for further processing */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)(packet);

  printf("IP Packet Received...\n");
  fprintf(stderr, "\tsource IP: ");
  print_addr_ip_int(ntohl(ip_header->ip_src));
  fprintf(stderr, "\tsource MAC: ");
  print_addr_eth(eth_header->ether_shost);
  fprintf(stderr, "\tdestination IP: ");
  print_addr_ip_int(ntohl(ip_header->ip_dst));
  fprintf(stderr, "\tdestination MAC: ");
  print_addr_eth(eth_header->ether_dhost);

  /* Decrement TTL and recompute checksum */
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum((const void*)ip_header, sizeof(sr_ip_hdr_t));  

  struct sr_if* pkt_interface = 0;
  struct sr_if* interface_list_iterator = sr->if_list;

  /* If destination address belongs to Router's if_list */
  while (interface_list_iterator!=NULL) 
  {
    if (ip_header->ip_dst == interface_list_iterator->ip) 
        pkt_interface = interface_list_iterator;
    interface_list_iterator = interface_list_iterator->next;
  }

  /* IP packet destined for router's interface - NO GO */
  /* Processing only for ICMP echo request-reply otherwise no go */
  
  if (pkt_interface!=0) /* Interface record exists */
  { 
    printf("IP Packet meant for Router...\n");
    if (ip_header->ip_p == ip_protocol_icmp) /* echo req/reply */
    {
      printf("IP Packet contains ICMP...\n");
      sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if (icmp_header->icmp_type == 8) /* PING */
      {
          printf("ICMP Echo request to Router...\n");

          uint8_t* send_packet = (uint8_t *)malloc(len);
          /* Same content as packet */
          memcpy(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
          /* ICMP header */
          sr_icmp_hdr_t* new_icmp = (sr_icmp_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          new_icmp->icmp_type = 0;
          new_icmp->icmp_code = 0;
          new_icmp->icmp_sum = cksum(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), len - sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          /* Ethernet header */
          sr_ethernet_hdr_t *new_ethhdr = (sr_ethernet_hdr_t *) send_packet;
          new_ethhdr->ether_type = ntohs(0x0800);
          /* IP header */
          sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t));
          new_iphdr->ip_len = ntohs(len - sizeof(sr_ethernet_hdr_t));
          new_iphdr->ip_ttl = 64; /* 64 */
          new_iphdr->ip_v = 4;
          new_iphdr->ip_hl = 5;
          new_iphdr->ip_dst = ip_header->ip_src;
          new_iphdr->ip_src = ip_header->ip_dst;
          new_iphdr->ip_p = 0x0001;
          new_iphdr->ip_sum = 0;
          new_iphdr->ip_sum = cksum(send_packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

          printf("ICMP Echo response prepared...\n");
          struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), new_iphdr->ip_dst);
          if (arp_entry)
          {
            memcpy(new_ethhdr->ether_dhost, arp_entry->mac, 6);
            struct sr_if* sending_interface = sr_get_interface(sr, interface);
            memcpy(new_ethhdr->ether_shost, sending_interface->addr, 6);
            sr_send_packet(sr, send_packet, len, interface);
            printf("ICMP Echo response sent (Cache lookup successful)...\n");
            free(arp_entry);
          }
          else
          {
            printf("Entry not found in Cache for ICMP Echo response (Preparing ARP Request)...\n");
            struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), new_iphdr->ip_dst, send_packet, len, interface);
            req->iface = interface;
            handle_arpreq(sr, req);
          }
          free (send_packet);
          return;
      }
      else 
      {
        /* Drop DA packet*/
        printf("Non-PING ICMP to Router. Packet will be dropped...\n");
      }
    } 

    /*receive a TCP/UDP packet, send ICMP port unreachable back*/

    else if(ip_header->ip_p == 0x06 || ip_header->ip_p == 0x11)
    {
        printf("TCP/UDP packet to Router...\n");

        size_t tulen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        uint8_t* send_packet = malloc(tulen);
        sr_ethernet_hdr_t* new_ether_header = (sr_ethernet_hdr_t*)send_packet;
        sr_ip_hdr_t* new_ip_header = (sr_ip_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t* new_icmp_header = (sr_icmp_t3_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /*write ethernet header*/
        struct sr_if* sending_interface = sr_get_interface(sr, interface);
        memcpy(new_ether_header->ether_dhost, eth_header->ether_shost, 6);
        memcpy(new_ether_header->ether_shost, sending_interface->addr, 6);
        new_ether_header->ether_type = htons(0x0800);

        /*write ip header*/
        new_ip_header->ip_hl = 5;
        new_ip_header->ip_v = 4;
        new_ip_header->ip_tos = ip_header->ip_tos;
        new_ip_header->ip_len = htons( sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        new_ip_header->ip_id = ip_header->ip_id;
        new_ip_header->ip_off = htons(0x4000);
        new_ip_header->ip_ttl = 64;
        new_ip_header->ip_p = ip_protocol_icmp;
        new_ip_header->ip_sum = 0;
        new_ip_header->ip_src = sending_interface->ip;
        new_ip_header->ip_dst = ip_header->ip_src;
        new_ip_header->ip_sum = cksum(new_ip_header, sizeof(sr_ip_hdr_t));

        /*write icmp header*/
        new_icmp_header->icmp_type = 3;
        new_icmp_header->icmp_code = 3;
        new_icmp_header->icmp_sum = 0;
        new_icmp_header->next_mtu = htons(512);
        memcpy(new_icmp_header->data, (uint8_t *)ip_header, 28);
        /*memcpy(new_icmp_header->data + sizeof(sr_ip_hdr_t), send_packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), 8);*/
        new_icmp_header->icmp_sum = cksum(send_packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), sizeof(sr_icmp_t3_hdr_t));

        printf("Port Unreachable: Sending ICMP (3,3)...\n");
        /*send packet*/
        sr_send_packet(sr, send_packet, tulen, interface);
        free(send_packet);
        return;
    } 
    else
    {
      printf("Unknown IP protocol number to Router. Packet will be dropeed...\n");
    }
  } 


  else 
  {
     printf("IP Packet not meant for router...\n");
    /* Forward the Packet  */
    printf("Preparing to forward...\n");

    struct sr_rt* next_hop = NULL;
    struct sr_rt* table_iterator = sr->routing_table;
    while (table_iterator) 
    {
      if ((ip_header->ip_dst & (table_iterator->mask).s_addr) == ((table_iterator->dest).s_addr & (table_iterator->mask).s_addr)) 
        next_hop = table_iterator;
      table_iterator = table_iterator->next;
    }

    /* If no matching entry in Routing Table. Send Destination Net Unreachable */

    if (next_hop == NULL)
    {
        printf("Non existent route to destination IP...\n");

        size_t tulen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        uint8_t* send_packet = malloc(tulen);
        sr_ethernet_hdr_t* new_ether_header = (sr_ethernet_hdr_t*)send_packet;
        sr_ip_hdr_t* new_ip_header = (sr_ip_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t));
        sr_icmp_t3_hdr_t* new_icmp_header = (sr_icmp_t3_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /*write ethernet header*/
        struct sr_if* sending_interface = sr_get_interface(sr, interface);
        memcpy(new_ether_header->ether_dhost, eth_header->ether_shost, 6);
        memcpy(new_ether_header->ether_shost, sending_interface->addr, 6);
        new_ether_header->ether_type = htons(0x0800);

        /*write ip header*/
        new_ip_header->ip_hl = 5;
        new_ip_header->ip_v = 4;
        new_ip_header->ip_tos = ip_header->ip_tos;
        new_ip_header->ip_len = htons( sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        new_ip_header->ip_id = ip_header->ip_id;
        new_ip_header->ip_off = 0;
        new_ip_header->ip_ttl = 64;
        new_ip_header->ip_p = ip_protocol_icmp;
        new_ip_header->ip_sum = 0;
        new_ip_header->ip_src = sending_interface->ip;
        new_ip_header->ip_dst = ip_header->ip_src;
        new_ip_header->ip_sum = cksum(new_ip_header, sizeof(sr_ip_hdr_t));

        /*write icmp header*/
        new_icmp_header->icmp_type = 3;
        new_icmp_header->icmp_code = 0;
        new_icmp_header->icmp_sum = 0;
        new_icmp_header->next_mtu = htons(512);
        memcpy(new_icmp_header->data, (uint8_t *)ip_header, 28);
        /*memcpy(new_icmp_header->data + sizeof(sr_ip_hdr_t), send_packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), 8);*/
        new_icmp_header->icmp_sum = cksum(send_packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), sizeof(sr_icmp_t3_hdr_t));

        printf("Net Unreachable: Sending ICMP (3,0)...\n");
        /*send packet*/
        sr_send_packet(sr, send_packet, tulen, interface);
        free(send_packet);
        return;
    }

    /* Continue Forwarding otherwise */
    ip_header->ip_ttl--;

    if (ip_header->ip_ttl == 0) 
    {
        printf("Timed out (TTL = 0). IP packet will be discarded MUAHAHAHAH! ...\n");

        size_t tulen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
        uint8_t* send_packet = malloc(tulen);
        sr_ethernet_hdr_t* new_ether_header = (sr_ethernet_hdr_t*)send_packet;
        sr_ip_hdr_t* new_ip_header = (sr_ip_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t));
        sr_icmp_hdr_t* new_icmp_header = (sr_icmp_hdr_t*)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /*write ethernet header*/
        struct sr_if* sending_interface = sr_get_interface(sr, interface);
        memcpy(new_ether_header->ether_dhost, eth_header->ether_shost, 6);
        memcpy(new_ether_header->ether_shost, sending_interface->addr, 6);
        new_ether_header->ether_type = htons(0x0800);

        /*write ip header*/
        new_ip_header->ip_hl = 5;
        new_ip_header->ip_v = 4;
        new_ip_header->ip_tos = ip_header->ip_tos;
        new_ip_header->ip_len = htons( sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        new_ip_header->ip_id = ip_header->ip_id;
        new_ip_header->ip_off = 0;
        new_ip_header->ip_ttl = 64;
        new_ip_header->ip_p = ip_protocol_icmp;
        new_ip_header->ip_sum = 0;
        new_ip_header->ip_src = sending_interface->ip;
        new_ip_header->ip_dst = ip_header->ip_src;
        new_ip_header->ip_sum = cksum(new_ip_header, sizeof(sr_ip_hdr_t));

        /*write icmp header*/
        new_icmp_header->icmp_type = 11;
        new_icmp_header->icmp_code = 0;
        new_icmp_header->icmp_sum = 0;
        new_icmp_header->icmp_sum = cksum(send_packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), sizeof(sr_icmp_t3_hdr_t));

        printf("Time Exceeded: Sending ICMP (11,0)...\n");
        /*send packet*/
        sr_send_packet(sr, send_packet, tulen, interface);
        free(send_packet);
        return;      
    }

    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum((uint8_t*) ip_header, sizeof(sr_ip_hdr_t));

    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), next_hop->gw.s_addr);
    if (arp_entry) 
    {
      sr_ethernet_hdr_t* new_etheader = (sr_ethernet_hdr_t *)(packet);
      struct sr_if* interface = sr_get_interface(sr, next_hop->interface);
      memcpy(new_etheader->ether_dhost, arp_entry->mac, 6);
      memcpy(new_etheader->ether_shost, interface->addr, 6);
      printf("Packet forwarded (Cache lookup successful)...\n");
      sr_send_packet(sr, packet, len, next_hop->interface);
      free(arp_entry);
    }
    else 
    {
      printf("Forwarding Entry not found in Cache (Preparing ARP Request)...\n");
      struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), next_hop->gw.s_addr, packet, len, next_hop->interface);
      req->iface = next_hop->interface;
      handle_arpreq(sr, req);
    }
  }              
}


void process_ether_type_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* iface/* lent */)
{
/* Router receives an ARP packet  */
  assert(sr);
  assert(packet);
  assert(iface);

  printf("ARP Packet Received...\n");
  /* Create ARP Header and find interface */
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_header->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_header->ar_sip));
  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_header->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_header->ar_tip));

  struct sr_if* interface = NULL;
  struct sr_if* interface_list_iterator = sr->if_list;

  while (interface_list_iterator!=NULL) 
  {
    if (arp_header->ar_tip == interface_list_iterator->ip) 
        interface = interface_list_iterator;
    interface_list_iterator = interface_list_iterator->next;
  }

  unsigned short op_code = ntohs(arp_header->ar_op);

  /* If ARP req/response is meant for router the process else drop/forward */
  /* The following code gets executed when you first PING to a router's interface
    and the client does not know the router's MAC */

  if (interface!=0)
  {
    if (op_code == 0x0001) 
    { /* Process ARP Request */
      printf("ARP Request for Router detected...\n");

      sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)(packet);
      memcpy(arp_header->ar_tha, arp_header->ar_sha, 6);
      memcpy(arp_header->ar_sha, interface->addr, 6);
      memcpy(ethernet_hdr->ether_dhost, arp_header->ar_tha, 6);
      memcpy(ethernet_hdr->ether_shost, arp_header->ar_sha, 6);
      arp_header->ar_tip = arp_header->ar_sip;
      arp_header->ar_sip = interface->ip;
      arp_header->ar_op = htons(0x0002);

      printf("Router sent ARP Reply...\n");
      sr_send_packet(sr, packet, len, iface);
    }

    if (op_code == 0x0002) 
    { /* Process ARP Reply */
      printf("Router received ARP Reply...\n");

      /* See if there's an ARP request in the queue. */
      struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
      struct sr_packet* pckt = req ? req->packets : NULL;

      for (; pckt != NULL; pckt = pckt->next) 
      {
        printf("Forwarding all packets waiting for this Reply...\n");
        sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t *)(pckt->buf);
        struct sr_if* sending_interface = sr_get_interface(sr, pckt->iface);
        memcpy(ethernet_hdr->ether_dhost, arp_header->ar_sha, 6);
        memcpy(ethernet_hdr->ether_shost, sending_interface->addr, 6);
        sr_send_packet(sr, pckt->buf, pckt->len, pckt->iface);
      }
    } 
  }
}