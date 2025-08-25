#pragma once

// Mock pcap.h for testing purposes
// This allows compilation without the actual libpcap library

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

// Mock pcap structures
struct pcap_pkthdr {
    struct timeval ts;  // time stamp
    uint32_t caplen;    // length of portion present
    uint32_t len;       // length of this packet (off wire)
};

// Forward declarations
struct pcap;
struct pcap_dumper;
struct pcap_if;
struct pcap_addr;
struct bpf_program;
struct bpf_insn;
struct pcap_stat;

typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;
typedef struct pcap_if pcap_if_t;
typedef struct pcap_addr pcap_addr_t;

// Mock pcap_if_t structure
struct pcap_if {
    struct pcap_if* next;
    char* name;
    char* description;
    struct pcap_addr* addresses;
    uint32_t flags;
};

// Mock pcap_addr structure
struct pcap_addr {
    struct pcap_addr* next;
    struct sockaddr* addr;
    struct sockaddr* netmask;
    struct sockaddr* broadaddr;
    struct sockaddr* dstaddr;
};

// Mock bpf_program structure
struct bpf_program {
    uint32_t bf_len;
    struct bpf_insn* bf_insns;
};

// Mock bpf_insn structure
struct bpf_insn {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

// Mock pcap_stat structure
struct pcap_stat {
    uint32_t ps_recv;
    uint32_t ps_drop;
    uint32_t ps_ifdrop;
};

// Mock constants
#define PCAP_ERRBUF_SIZE 256
#define PCAP_IF_LOOPBACK 0x00000001
#define PCAP_IF_UP 0x00000002
#define PCAP_IF_RUNNING 0x00000004
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#define PCAP_ERROR -1

// Mock datalink types
#define DLT_NULL 0
#define DLT_EN10MB 1
#define DLT_EN3MB 2
#define DLT_AX25 3
#define DLT_PRONET 4
#define DLT_CHAOS 5
#define DLT_IEEE802 6
#define DLT_ARCNET 7
#define DLT_SLIP 8
#define DLT_PPP 9
#define DLT_FDDI 10
#define DLT_RAW 12
#define DLT_IEEE802_11 105
#define DLT_LINUX_SLL 113
#define DLT_LINUX_IRDA 144
#define DLT_LINUX_LAPD 177
#define DLT_LINUX_USB 220
#define DLT_LINUX_SLL2 276

// Mock pcap functions
extern "C" {
    typedef void (*pcap_handler)(u_char*, const struct pcap_pkthdr*, const u_char*);
    
    pcap_t* pcap_open_live(const char* device, int snaplen, int promisc, int to_ms, char* errbuf);
    pcap_t* pcap_open_offline(const char* fname, char* errbuf);
    void pcap_close(pcap_t* p);
    int pcap_loop(pcap_t* p, int cnt, void (*callback)(u_char*, const struct pcap_pkthdr*, const u_char*), u_char* user);
    int pcap_dispatch(pcap_t* p, int cnt, void (*callback)(u_char*, const struct pcap_pkthdr*, const u_char*), u_char* user);
    const u_char* pcap_next(pcap_t* p, struct pcap_pkthdr* h);
    int pcap_next_ex(pcap_t* p, struct pcap_pkthdr** pkt_header, const u_char** pkt_data);
    int pcap_compile(pcap_t* p, struct bpf_program* fp, const char* str, int optimize, uint32_t netmask);
    void pcap_freecode(struct bpf_program* fp);
    int pcap_setfilter(pcap_t* p, struct bpf_program* fp);
    char* pcap_geterr(pcap_t* p);
    int pcap_stats(pcap_t* p, struct pcap_stat* ps);
    int pcap_setnonblock(pcap_t* p, int nonblock, char* errbuf);
    int pcap_getnonblock(pcap_t* p, char* errbuf);
    int pcap_inject(pcap_t* p, const void* buf, size_t size);
    int pcap_sendpacket(pcap_t* p, const u_char* buf, int size);
    pcap_dumper_t* pcap_dump_open(pcap_t* p, const char* fname);
    void pcap_dump(u_char* user, const struct pcap_pkthdr* h, const u_char* sp);
    void pcap_dump_close(pcap_dumper_t* p);
    int pcap_dump_flush(pcap_dumper_t* p);
    int pcap_findalldevs(pcap_if_t** alldevsp, char* errbuf);
    void pcap_freealldevs(pcap_if_t* alldevsp);
    char* pcap_lookupdev(char* errbuf);
    int pcap_lookupnet(const char* device, uint32_t* netp, uint32_t* maskp, char* errbuf);
    int pcap_datalink(pcap_t* p);
    int pcap_snapshot(pcap_t* p);
    int pcap_is_swapped(pcap_t* p);
    int pcap_major_version(pcap_t* p);
    int pcap_minor_version(pcap_t* p);
    FILE* pcap_file(pcap_t* p);
    int pcap_fileno(pcap_t* p);
    int pcap_dump_file(pcap_dumper_t* p);
    int pcap_dump_ftell(pcap_dumper_t* p);
    long pcap_ftell(pcap_t* p);
    int pcap_seek(pcap_t* p, long offset);
    int pcap_dump_ftell64(pcap_dumper_t* p);
    int64_t pcap_ftell64(pcap_t* p);
    int pcap_seek64(pcap_t* p, int64_t offset);
    int pcap_set_tstamp_precision(pcap_t* p, int tstamp_precision);
    int pcap_get_tstamp_precision(pcap_t* p);
    int pcap_set_tstamp_type(pcap_t* p, int tstamp_type);
    int pcap_list_tstamp_types(pcap_t* p, int** tstamp_typesp);
    void pcap_free_tstamp_types(int* tstamp_types);
    int pcap_tstamp_type_name_to_val(const char* name);
    const char* pcap_tstamp_type_val_to_name(int tstamp_type);
    const char* pcap_tstamp_type_val_to_description(int tstamp_type);
    int pcap_set_immediate_mode(pcap_t* p, int immediate);
    int pcap_set_buffer_size(pcap_t* p, int buffer_size);
    int pcap_set_promisc(pcap_t* p, int promisc);
    int pcap_set_rfmon(pcap_t* p, int rfmon);
    int pcap_set_timeout(pcap_t* p, int timeout_ms);
    int pcap_set_snaplen(pcap_t* p, int snaplen);
    int pcap_activate(pcap_t* p);
    int pcap_list_datalinks(pcap_t* p, int** dlt_bufp);
    void pcap_free_datalinks(int* dlt_list);
    int pcap_set_datalink(pcap_t* p, int dlt);
    int pcap_datalink_name_to_val(const char* name);
    const char* pcap_datalink_val_to_name(int dlt);
    const char* pcap_datalink_val_to_description(int dlt);
}
