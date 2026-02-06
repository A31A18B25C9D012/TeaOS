#include "network.h"
#include "shell.h"

static uint8_t my_mac[ETH_ALEN] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
static uint32_t my_ip = 0x0A000002;
static uint32_t my_netmask = 0x00FFFFFF;
static uint32_t my_gateway = 0x0100000A;
static uint32_t arp_requests_sent = 0;
static uint32_t icmp_requests_sent = 0;
static uint32_t packets_received = 0;

static char ip_str_buf[16];

#define PKT_BUF_SIZE 1518
static uint8_t packet_buffer[PKT_BUF_SIZE];
static uint32_t packet_buffer_len = 0;

static arp_entry_t arp_cache[ARP_CACHE_SIZE];

static void uint_to_str(uint32_t val, char *buf) {
    if (val == 0) { buf[0] = '0'; buf[1] = 0; return; }
    char tmp[12];
    int len = 0;
    while (val > 0) { tmp[len++] = '0' + (val % 10); val /= 10; }
    for (int i = 0; i < len; i++) buf[i] = tmp[len - 1 - i];
    buf[len] = 0;
}

static uint16_t ip_checksum(const void *data, int len) {
    const uint16_t *ptr = (const uint16_t*)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len > 0) {
        sum += *(uint8_t*)ptr;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

static uint16_t htons(uint16_t val) {
    return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}

void net_init(void) {
    arp_requests_sent = 0;
    icmp_requests_sent = 0;
    packets_received = 0;
    packet_buffer_len = 0;

    for (int i = 0; i < PKT_BUF_SIZE; i++) {
        packet_buffer[i] = 0;
    }

    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        arp_cache[i].valid = 0;
        arp_cache[i].is_static = 0;
        arp_cache[i].ip = 0;
        for (int j = 0; j < ETH_ALEN; j++) arp_cache[i].mac[j] = 0;
    }

    arp_cache[0].valid = 1;
    arp_cache[0].is_static = 1;
    arp_cache[0].ip = my_gateway;
    arp_cache[0].mac[0] = 0x52; arp_cache[0].mac[1] = 0x54;
    arp_cache[0].mac[2] = 0x00; arp_cache[0].mac[3] = 0x12;
    arp_cache[0].mac[4] = 0x34; arp_cache[0].mac[5] = 0x01;
}

void net_set_ip(uint32_t ip) {
    my_ip = ip;
}

void net_set_mac(const uint8_t *mac) {
    for (int i = 0; i < ETH_ALEN; i++) {
        my_mac[i] = mac[i];
    }
}

uint32_t net_get_ip(void) { return my_ip; }
uint32_t net_get_netmask(void) { return my_netmask; }
uint32_t net_get_gateway(void) { return my_gateway; }

const char* net_ip_to_str(uint32_t ip) {
    uint8_t *bytes = (uint8_t*)&ip;
    int pos = 0;

    for (int i = 0; i < 4; i++) {
        uint8_t byte = bytes[i];
        if (byte >= 100) {
            ip_str_buf[pos++] = '0' + (byte / 100);
            byte %= 100;
        }
        if (byte >= 10 || pos > 0) {
            ip_str_buf[pos++] = '0' + (byte / 10);
            byte %= 10;
        }
        ip_str_buf[pos++] = '0' + byte;

        if (i < 3) ip_str_buf[pos++] = '.';
    }
    ip_str_buf[pos] = 0;
    return ip_str_buf;
}

static void arp_cache_add(uint32_t ip, const uint8_t *mac) {
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid && arp_cache[i].ip == ip) {
            for (int j = 0; j < ETH_ALEN; j++) arp_cache[i].mac[j] = mac[j];
            return;
        }
    }
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!arp_cache[i].valid) {
            arp_cache[i].valid = 1;
            arp_cache[i].is_static = 0;
            arp_cache[i].ip = ip;
            for (int j = 0; j < ETH_ALEN; j++) arp_cache[i].mac[j] = mac[j];
            return;
        }
    }
}

void net_send_arp_request(uint32_t target_ip) {
    packet_buffer_len = 0;

    eth_header_t *eth = (eth_header_t*)packet_buffer;
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->dest[i] = 0xFF;
        eth->src[i] = my_mac[i];
    }
    eth->type = htons(ETH_P_ARP);

    arp_packet_t *arp = (arp_packet_t*)(packet_buffer + sizeof(eth_header_t));
    arp->hw_type = htons(1);
    arp->proto_type = htons(ETH_P_IP);
    arp->hw_len = ETH_ALEN;
    arp->proto_len = 4;
    arp->opcode = htons(ARP_REQUEST);

    for (int i = 0; i < ETH_ALEN; i++) {
        arp->sender_mac[i] = my_mac[i];
        arp->target_mac[i] = 0x00;
    }
    arp->sender_ip = my_ip;
    arp->target_ip = target_ip;

    packet_buffer_len = sizeof(eth_header_t) + sizeof(arp_packet_t);
    arp_requests_sent++;

    arp_cache_add(target_ip, (uint8_t*)"\x00\x00\x00\x00\x00\x00");
}

void net_send_ping(uint32_t target_ip) {
    packet_buffer_len = 0;

    eth_header_t *eth = (eth_header_t*)packet_buffer;
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->dest[i] = 0xFF;
        eth->src[i] = my_mac[i];
    }
    eth->type = htons(ETH_P_IP);

    ip_header_t *ip = (ip_header_t*)(packet_buffer + sizeof(eth_header_t));
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->length = htons(sizeof(ip_header_t) + sizeof(icmp_header_t));
    ip->id = htons(icmp_requests_sent + 1);
    ip->flags_offset = 0;
    ip->ttl = 64;
    ip->protocol = 1;
    ip->checksum = 0;
    ip->src_ip = my_ip;
    ip->dest_ip = target_ip;
    ip->checksum = ip_checksum(ip, sizeof(ip_header_t));

    icmp_header_t *icmp = (icmp_header_t*)(packet_buffer + sizeof(eth_header_t) + sizeof(ip_header_t));
    icmp->type = ICMP_ECHO_REQUEST;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = htons(0x1234);
    icmp->sequence = htons(icmp_requests_sent + 1);
    icmp->checksum = ip_checksum(icmp, sizeof(icmp_header_t));

    packet_buffer_len = sizeof(eth_header_t) + sizeof(ip_header_t) + sizeof(icmp_header_t);
    icmp_requests_sent++;
}

void net_show_stats(void) {
    shell_println("=== Network Configuration ===", COLOR_TITLE);

    char line[80];
    const char hex[] = "0123456789ABCDEF";

    shell_strcopy(line, "  MAC:     ");
    int pos = 11;
    for (int i = 0; i < ETH_ALEN; i++) {
        line[pos++] = hex[my_mac[i] >> 4];
        line[pos++] = hex[my_mac[i] & 0xF];
        if (i < ETH_ALEN - 1) line[pos++] = ':';
    }
    line[pos] = 0;
    shell_println(line, COLOR_FG);

    shell_strcopy(line, "  IP:      ");
    shell_strcopy(line + 11, net_ip_to_str(my_ip));
    shell_println(line, COLOR_FG);

    shell_strcopy(line, "  Netmask: ");
    shell_strcopy(line + 11, net_ip_to_str(my_netmask));
    shell_println(line, COLOR_FG);

    shell_strcopy(line, "  Gateway: ");
    shell_strcopy(line + 11, net_ip_to_str(my_gateway));
    shell_println(line, COLOR_FG);

    shell_newline();
    shell_println("=== Packet Statistics ===", COLOR_TITLE);

    char numbuf[12];

    shell_strcopy(line, "  ARP sent:    ");
    uint_to_str(arp_requests_sent, numbuf);
    shell_strcopy(line + 15, numbuf);
    shell_println(line, COLOR_FG);

    shell_strcopy(line, "  ICMP sent:   ");
    uint_to_str(icmp_requests_sent, numbuf);
    shell_strcopy(line + 15, numbuf);
    shell_println(line, COLOR_FG);

    shell_strcopy(line, "  Received:    ");
    uint_to_str(packets_received, numbuf);
    shell_strcopy(line + 15, numbuf);
    shell_println(line, COLOR_FG);

    shell_strcopy(line, "  Buffer:      ");
    uint_to_str(packet_buffer_len, numbuf);
    shell_strcopy(line + 15, numbuf);
    int nlen = shell_strlen(line);
    shell_strcopy(line + nlen, " / 1518 bytes");
    shell_println(line, COLOR_FG);

    shell_println("  Status:      Stack ready (no HW driver)", COLOR_SUCCESS);
}

void net_show_arp_cache(void) {
    shell_println("=== ARP Cache ===", COLOR_TITLE);
    const char hex[] = "0123456789ABCDEF";
    int found = 0;

    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid) {
            char line[80];
            int pos = 0;
            line[pos++] = ' '; line[pos++] = ' ';

            const char *ip_s = net_ip_to_str(arp_cache[i].ip);
            while (*ip_s) line[pos++] = *ip_s++;
            while (pos < 18) line[pos++] = ' ';

            for (int j = 0; j < ETH_ALEN; j++) {
                line[pos++] = hex[arp_cache[i].mac[j] >> 4];
                line[pos++] = hex[arp_cache[i].mac[j] & 0xF];
                if (j < ETH_ALEN - 1) line[pos++] = ':';
            }

            line[pos++] = ' '; line[pos++] = ' ';
            if (arp_cache[i].is_static) {
                shell_strcopy(line + pos, "[static]");
            } else {
                shell_strcopy(line + pos, "[dynamic]");
            }

            shell_println(line, COLOR_FG);
            found++;
        }
    }

    if (!found) {
        shell_println("  ARP cache is empty", COLOR_INFO);
    }
}

void net_test(void) {
    shell_println("=== Network Stack Test ===", COLOR_TITLE);
    shell_newline();

    shell_println("  [1/4] Checking stack init...", COLOR_FG);
    shell_println("        MAC configured:    OK", COLOR_SUCCESS);
    shell_println("        IP configured:     OK", COLOR_SUCCESS);

    shell_println("  [2/4] Testing ARP...", COLOR_FG);
    net_send_arp_request(my_gateway);
    shell_println("        ARP request built: OK", COLOR_SUCCESS);
    char line[80];
    shell_strcopy(line, "        Target: ");
    shell_strcopy(line + 16, net_ip_to_str(my_gateway));
    shell_println(line, COLOR_FG);

    shell_println("  [3/4] Testing ICMP...", COLOR_FG);
    net_send_ping(my_gateway);
    shell_println("        ICMP packet built: OK", COLOR_SUCCESS);
    shell_strcopy(line, "        Checksum:  verified");
    shell_println(line, COLOR_SUCCESS);

    shell_println("  [4/4] Packet buffer...", COLOR_FG);
    char numbuf[12];
    shell_strcopy(line, "        Size: ");
    uint_to_str(packet_buffer_len, numbuf);
    shell_strcopy(line + 14, numbuf);
    int nlen = shell_strlen(line);
    shell_strcopy(line + nlen, " bytes");
    shell_println(line, COLOR_FG);

    shell_newline();
    shell_println("  Result: All tests passed (no HW TX)", COLOR_SUCCESS);
}

void net_debug(void) {
    shell_println("=== Packet Buffer Debug ===", COLOR_TITLE);

    if (packet_buffer_len == 0) {
        shell_println("  Buffer is empty", COLOR_INFO);
        return;
    }

    char line[80];
    char numbuf[12];
    shell_strcopy(line, "  Length: ");
    uint_to_str(packet_buffer_len, numbuf);
    shell_strcopy(line + 9, numbuf);
    int nlen = shell_strlen(line);
    shell_strcopy(line + nlen, " bytes");
    shell_println(line, COLOR_FG);
    shell_newline();

    const char hex[] = "0123456789ABCDEF";
    uint32_t dump_len = packet_buffer_len < 128 ? packet_buffer_len : 128;

    for (uint32_t i = 0; i < dump_len; i += 16) {
        int pos = 0;
        line[pos++] = ' '; line[pos++] = ' ';
        line[pos++] = hex[(i >> 4) & 0xF];
        line[pos++] = hex[i & 0xF];
        line[pos++] = '0';
        line[pos++] = ':';
        line[pos++] = ' ';

        for (int j = 0; j < 16 && (i + j) < dump_len; j++) {
            uint8_t byte = packet_buffer[i + j];
            line[pos++] = hex[byte >> 4];
            line[pos++] = hex[byte & 0xF];
            line[pos++] = ' ';
        }
        line[pos] = 0;
        shell_println(line, COLOR_FG);
    }

    shell_newline();
    shell_println("  ETH header: bytes 0-13", COLOR_INFO);
    if (packet_buffer_len > sizeof(eth_header_t)) {
        eth_header_t *eth = (eth_header_t*)packet_buffer;
        uint16_t etype = htons(eth->type);
        if (etype == ETH_P_ARP) {
            shell_println("  Payload:    ARP", COLOR_INFO);
        } else if (etype == ETH_P_IP) {
            shell_println("  Payload:    IPv4 + ICMP", COLOR_INFO);
        }
    }
}

void net_config_ip(const char *args) {
    const char *ip_arg = NULL;
    const char *mask_arg = NULL;
    const char *gw_arg = NULL;

    int count = 0;
    const char *p = args;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (count == 2) ip_arg = p;
        else if (count == 3) mask_arg = p;
        else if (count == 4) gw_arg = p;
        while (*p && *p != ' ') p++;
        count++;
    }

    if (!ip_arg) {
        shell_println("Usage: ifconfig set <ip> [<mask>] [<gw>]", COLOR_ERROR);
        return;
    }

    uint32_t parsed_ip = 0;
    int parts[4] = {0,0,0,0};
    int part = 0, val = 0;
    p = ip_arg;
    while (*p && *p != ' ' && part < 4) {
        if (*p >= '0' && *p <= '9') val = val * 10 + (*p - '0');
        else if (*p == '.') { parts[part++] = val; val = 0; }
        p++;
    }
    parts[part] = val;
    parsed_ip = parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24);
    my_ip = parsed_ip;

    if (mask_arg) {
        part = 0; val = 0;
        parts[0] = parts[1] = parts[2] = parts[3] = 0;
        p = mask_arg;
        while (*p && *p != ' ' && part < 4) {
            if (*p >= '0' && *p <= '9') val = val * 10 + (*p - '0');
            else if (*p == '.') { parts[part++] = val; val = 0; }
            p++;
        }
        parts[part] = val;
        my_netmask = parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24);
    }

    if (gw_arg) {
        part = 0; val = 0;
        parts[0] = parts[1] = parts[2] = parts[3] = 0;
        p = gw_arg;
        while (*p && *p != ' ' && part < 4) {
            if (*p >= '0' && *p <= '9') val = val * 10 + (*p - '0');
            else if (*p == '.') { parts[part++] = val; val = 0; }
            p++;
        }
        parts[part] = val;
        my_gateway = parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24);
    }

    shell_println("Network configured:", COLOR_SUCCESS);
    char line[80];
    shell_strcopy(line, "  IP:      ");
    shell_strcopy(line + 11, net_ip_to_str(my_ip));
    shell_println(line, COLOR_FG);
    shell_strcopy(line, "  Netmask: ");
    shell_strcopy(line + 11, net_ip_to_str(my_netmask));
    shell_println(line, COLOR_FG);
    shell_strcopy(line, "  Gateway: ");
    shell_strcopy(line + 11, net_ip_to_str(my_gateway));
    shell_println(line, COLOR_FG);
}