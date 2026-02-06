#ifndef NETWORK_H
#define NETWORK_H

#include "types.h"

#define ETH_ALEN 6
#define ETH_P_ARP 0x0806
#define ETH_P_IP  0x0800

#define ARP_REQUEST 1
#define ARP_REPLY   2

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0

#define ARP_CACHE_SIZE 8

typedef struct {
    uint8_t dest[ETH_ALEN];
    uint8_t src[ETH_ALEN];
    uint16_t type;
} __attribute__((packed)) eth_header_t;

typedef struct {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_len;
    uint8_t proto_len;
    uint16_t opcode;
    uint8_t sender_mac[ETH_ALEN];
    uint32_t sender_ip;
    uint8_t target_mac[ETH_ALEN];
    uint32_t target_ip;
} __attribute__((packed)) arp_packet_t;

typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t length;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} __attribute__((packed)) ip_header_t;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} __attribute__((packed)) icmp_header_t;

typedef struct {
    uint32_t ip;
    uint8_t mac[ETH_ALEN];
    uint8_t valid;
    uint8_t is_static;
} arp_entry_t;

void net_init(void);
void net_set_ip(uint32_t ip);
void net_set_mac(const uint8_t *mac);
void net_send_arp_request(uint32_t target_ip);
void net_send_ping(uint32_t target_ip);
void net_show_stats(void);
const char* net_ip_to_str(uint32_t ip);
void net_show_arp_cache(void);
void net_test(void);
void net_debug(void);
void net_config_ip(const char *args);
uint32_t net_get_ip(void);
uint32_t net_get_netmask(void);
uint32_t net_get_gateway(void);

#endif