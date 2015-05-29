#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) 
{ 
  struct sr_arpreq* req = sr->cache.requests;
    while(req != NULL)
    {
        handle_arpreq(sr, req);
        req = req->next;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}


int handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req) 
{
  printf("Handling Request from queue...\n");

  time_t cur_time = time(NULL);
  if (difftime(cur_time, req->sent) > 1.0) 
  {
    if (req->times_sent >= 5) 
    {
      size_t icmp_size = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
      struct sr_packet *cur_packet = req->packets;
      while(cur_packet != NULL)
      {
        uint8_t *new_icmp_packet;
        new_icmp_packet = generate_icmp_message(cur_packet, sr);
        printf("Sending ICMP (3,1)...\n");
        sr_send_packet(sr, new_icmp_packet, icmp_size, cur_packet->iface);
        cur_packet = cur_packet->next;
      }
    sr_arpreq_destroy(&(sr->cache), req);        
    } 
    else 
    {
        size_t arp_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        struct sr_if* cur_if = sr_get_interface(sr, req->iface);
        uint8_t *new_arp_packet = generate_arp_request(req, cur_if);
        printf("Sending routine ARP Request from handle_arpreq...\n");
        sr_send_packet(sr, new_arp_packet, arp_size, cur_if->name);
        req->sent = time(NULL);
        req->times_sent++;
        free(new_arp_packet);
    }
  }
return 0;
}

/*
Generate ICMP packet
*/
uint8_t *generate_icmp_message(struct sr_packet *cur_packet, struct sr_instance *sr)
{
    size_t packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

    uint8_t *newpacket = (uint8_t*)malloc(packet_size);

    sr_ethernet_hdr_t *new_ethernet_header = (sr_ethernet_hdr_t*)(newpacket);
    sr_ip_hdr_t* new_ip_header = (sr_ip_hdr_t*)(newpacket + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *new_icmp_header = (sr_icmp_t3_hdr_t*)(newpacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /*set up ethernet header*/

    sr_ethernet_hdr_t *req_ether_header = (sr_ethernet_hdr_t*)(cur_packet->buf); /*ethernet header from buffer*/
    memcpy(new_ethernet_header->ether_shost, sr_get_interface(sr, cur_packet->iface)->addr, 6);
    memcpy(new_ethernet_header->ether_dhost, req_ether_header->ether_shost, 6);
    new_ethernet_header->ether_type = htons(ethertype_ip);

    /*set up ip header*/
    sr_ip_hdr_t *req_ip_header = (sr_ip_hdr_t*)(cur_packet->buf + sizeof(sr_ethernet_hdr_t)); /*ipv4 header from buffer*/
    new_ip_header->ip_hl = 5; /*minimum value is 5*/
    new_ip_header->ip_v = 4;
    new_ip_header->ip_tos = req_ip_header->ip_tos;
    new_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_ip_header->ip_off = 0; /*no fragment*/
    new_ip_header->ip_ttl = 64; /* recommanded initial value for TTL */
    new_ip_header->ip_p = ip_protocol_icmp;
    new_ip_header->ip_p = 0;
    new_ip_header->ip_sum = 0;
    new_ip_header->ip_src = sr_get_interface(sr,cur_packet->iface)->ip;
    new_ip_header->ip_dst = req_ip_header->ip_src;
    new_ip_header->ip_sum = cksum(newpacket + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

    /*set up type 3 icmp header*/

    new_icmp_header->icmp_type = 3;
    new_icmp_header->icmp_code = 1;
    new_icmp_header->icmp_sum = 0;
    new_icmp_header->next_mtu = 0;

    /*we need IP header and first 8 bytes of original datagram's data*/

    memcpy(new_icmp_header->data, (uint8_t *)req_ip_header, sizeof(sr_ip_hdr_t));
    memcpy((new_icmp_header->data + sizeof(sr_ip_hdr_t)), (newpacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)), 8);
    new_icmp_header->icmp_sum = cksum(new_icmp_header->data + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t), sizeof(sr_icmp_t3_hdr_t));
    return newpacket;
}


/*
Generate arp request and return a new packet
*/
uint8_t *generate_arp_request(struct sr_arpreq *req, struct sr_if* cur_if)
{
    size_t packet_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *newpacket = malloc(packet_size);
    sr_ethernet_hdr_t *new_ethernet_header = (sr_ethernet_hdr_t*)(newpacket);
    sr_arp_hdr_t *new_arp_header = (sr_arp_hdr_t*)(newpacket + sizeof(sr_ethernet_hdr_t));
    /*set ethernet header*/
    memcpy(new_ethernet_header->ether_shost, cur_if->addr, ETHER_ADDR_LEN);
    uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    memcpy(new_ethernet_header->ether_dhost, broadcast_addr, ETHER_ADDR_LEN);
    new_ethernet_header->ether_type = htons(ethertype_arp);
    /*set arp header*/
    new_arp_header->ar_hrd = htons(arp_hrd_ethernet);
    new_arp_header->ar_pro = htons(ethertype_ip);
    new_arp_header->ar_hln = ETHER_ADDR_LEN; /*mac address length*/
    new_arp_header->ar_pln = 4; /*ip address length( 4 for IPv4)*/
    new_arp_header->ar_op = htons(arp_op_request);
    memcpy(new_arp_header->ar_sha, cur_if->addr, ETHER_ADDR_LEN); /*sender hw address*/
    new_arp_header->ar_sip = cur_if->ip;
    memcpy(new_arp_header->ar_tha, broadcast_addr, ETHER_ADDR_LEN); /*target hw address*/
    new_arp_header->ar_tip = req->ip;
    /*DONE!*/
    return newpacket;
}


