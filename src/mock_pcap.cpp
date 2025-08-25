#include "../include/mock_pcap.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <thread>

// Mock pcap structure
struct pcap {
    std::string device_name;
    bool is_open;
    bool is_promiscuous;
    int snaplen;
    int timeout_ms;
    std::vector<std::string> mock_interfaces;
    
    pcap() : is_open(false), is_promiscuous(false), snaplen(65535), timeout_ms(1000) {
        // Add some mock interfaces
        mock_interfaces = {"eth0", "wlan0", "lo", "vEthernet (WSL)", "Ethernet"};
    }
};

struct pcap_dumper {
    std::string filename;
    bool is_open;
    
    pcap_dumper() : is_open(false) {}
};

// Mock global variables
static std::vector<pcap*> mock_pcap_handles;
static std::vector<pcap_dumper*> mock_dumper_handles;
static int mock_pcap_counter = 0;

// Mock pcap functions implementation
extern "C" {

pcap_t* pcap_open_live(const char* device, int snaplen, int promisc, int to_ms, char* errbuf) {
    (void)errbuf; // Suppress unused parameter warning
    auto* handle = new pcap();
    handle->device_name = device ? device : "mock_device";
    handle->snaplen = snaplen;
    handle->is_promiscuous = promisc != 0;
    handle->timeout_ms = to_ms;
    handle->is_open = true;
    
    mock_pcap_handles.push_back(handle);
    
    std::cout << "Mock pcap_open_live: " << device << " (snaplen=" << snaplen 
              << ", promisc=" << promisc << ", timeout=" << to_ms << "ms)" << std::endl;
    
    return handle;
}

pcap_t* pcap_open_offline(const char* fname, char* errbuf) {
    (void)errbuf; // Suppress unused parameter warning
    auto* handle = new pcap();
    handle->device_name = fname ? fname : "mock_file";
    handle->is_open = true;
    
    mock_pcap_handles.push_back(handle);
    
    std::cout << "Mock pcap_open_offline: " << fname << std::endl;
    
    return handle;
}

void pcap_close(pcap_t* p) {
    if (p) {
        p->is_open = false;
        std::cout << "Mock pcap_close: " << p->device_name << std::endl;
        
        // Remove from handles list
        auto it = std::find(mock_pcap_handles.begin(), mock_pcap_handles.end(), p);
        if (it != mock_pcap_handles.end()) {
            mock_pcap_handles.erase(it);
        }
        
        delete p;
    }
}

int pcap_loop(pcap_t* p, int cnt, void (*callback)(u_char*, const struct pcap_pkthdr*, const u_char*), u_char* user) {
    if (!p || !p->is_open) {
        return -1;
    }
    
    std::cout << "Mock pcap_loop: " << p->device_name << " (count=" << cnt << ")" << std::endl;
    
    // Generate some mock packets
    int packets_to_generate = (cnt <= 0) ? 10 : cnt;
    
    for (int i = 0; i < packets_to_generate; ++i) {
        // Create mock packet header
        struct pcap_pkthdr header;
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        header.ts.tv_sec = static_cast<long>(time_t);
        header.ts.tv_usec = static_cast<long>(std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()).count() % 1000000);
        header.caplen = 64 + i * 10;  // Mock packet size
        header.len = header.caplen;
        
        // Create mock packet data (realistic Ethernet + IP + TCP/UDP frame)
        std::vector<u_char> packet_data(header.caplen);
        
        // Ethernet header (14 bytes)
        if (packet_data.size() >= 14) {
            // Destination MAC: 00:11:22:33:44:55
            packet_data[0] = 0x00; packet_data[1] = 0x11; packet_data[2] = 0x22;
            packet_data[3] = 0x33; packet_data[4] = 0x44; packet_data[5] = 0x55;
            // Source MAC: AA:BB:CC:DD:EE:FF
            packet_data[6] = 0xAA; packet_data[7] = 0xBB; packet_data[8] = 0xCC;
            packet_data[9] = 0xDD; packet_data[10] = 0xEE; packet_data[11] = 0xFF;
            // EtherType: IPv4 (0x0800)
            packet_data[12] = 0x08; packet_data[13] = 0x00;
            
            // IP header (20 bytes minimum)
            if (packet_data.size() >= 34) {
                // Version (4) and IHL (5) = 0x45
                packet_data[14] = 0x45;
                // Type of Service
                packet_data[15] = 0x00;
                // Total Length (network byte order)
                uint16_t total_len = htons(packet_data.size() - 14);
                packet_data[16] = (total_len >> 8) & 0xFF;
                packet_data[17] = total_len & 0xFF;
                // Identification
                packet_data[18] = 0x12; packet_data[19] = 0x34;
                // Flags and Fragment Offset
                packet_data[20] = 0x40; packet_data[21] = 0x00; // Don't fragment
                // TTL
                packet_data[22] = 64;
                // Protocol (TCP = 6, UDP = 17)
                packet_data[23] = (i % 2 == 0) ? 6 : 17; // Alternate between TCP and UDP
                // Checksum (placeholder)
                packet_data[24] = 0x00; packet_data[25] = 0x00;
                // Source IP: 192.168.1.100
                packet_data[26] = 192; packet_data[27] = 168;
                packet_data[28] = 1; packet_data[29] = 100;
                // Destination IP: 192.168.1.1
                packet_data[30] = 192; packet_data[31] = 168;
                packet_data[32] = 1; packet_data[33] = 1;
                
                // TCP/UDP header
                if (packet_data.size() >= 54) {
                    if (packet_data[23] == 6) { // TCP
                        // Source port: 12345
                        packet_data[34] = 0x30; packet_data[35] = 0x39;
                        // Destination port: 80 (HTTP)
                        packet_data[36] = 0x00; packet_data[37] = 0x50;
                        // Sequence number
                        packet_data[38] = 0x00; packet_data[39] = 0x00;
                        packet_data[40] = 0x00; packet_data[41] = static_cast<u_char>(i);
                        // Acknowledgment number
                        packet_data[42] = 0x00; packet_data[43] = 0x00;
                        packet_data[44] = 0x00; packet_data[45] = 0x00;
                        // Data offset and flags
                        packet_data[46] = 0x50; // 5 words, no flags
                        packet_data[47] = 0x00;
                        // Window size
                        packet_data[48] = 0x20; packet_data[49] = 0x00;
                        // Checksum
                        packet_data[50] = 0x00; packet_data[51] = 0x00;
                        // Urgent pointer
                        packet_data[52] = 0x00; packet_data[53] = 0x00;
                    } else { // UDP
                        // Source port: 54321
                        packet_data[34] = 0xD4; packet_data[35] = 0x31;
                        // Destination port: 53 (DNS)
                        packet_data[36] = 0x00; packet_data[37] = 0x35;
                        // Length
                        uint16_t udp_len = htons(packet_data.size() - 34);
                        packet_data[38] = (udp_len >> 8) & 0xFF;
                        packet_data[39] = udp_len & 0xFF;
                        // Checksum
                        packet_data[40] = 0x00; packet_data[41] = 0x00;
                    }
                }
            }
        }
        
        // Call the callback
        callback(user, &header, packet_data.data());
        
        // Small delay to simulate real packet capture
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return 0;
}

int pcap_dispatch(pcap_t* p, int cnt, void (*callback)(u_char*, const struct pcap_pkthdr*, const u_char*), u_char* user) {
    return pcap_loop(p, cnt, callback, user);
}

const u_char* pcap_next(pcap_t* p, struct pcap_pkthdr* h) {
    if (!p || !p->is_open || !h) {
        return nullptr;
    }
    
    // Create mock packet header
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    h->ts.tv_sec = static_cast<long>(time_t);
    h->ts.tv_usec = static_cast<long>(std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count() % 1000000);
    h->caplen = 64;
    h->len = h->caplen;
    
    // Return mock packet data
    static std::vector<u_char> mock_packet(64);
    for (size_t i = 0; i < mock_packet.size(); ++i) {
        mock_packet[i] = static_cast<u_char>(i % 256);
    }
    
    return mock_packet.data();
}

int pcap_next_ex(pcap_t* p, struct pcap_pkthdr** pkt_header, const u_char** pkt_data) {
    if (!p || !p->is_open || !pkt_header || !pkt_data) {
        return -1;
    }
    
    // Create mock packet header
    static struct pcap_pkthdr header;
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    header.ts.tv_sec = static_cast<long>(time_t);
    header.ts.tv_usec = static_cast<long>(std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count() % 1000000);
    header.caplen = 64;
    header.len = header.caplen;
    
    *pkt_header = &header;
    
    // Create mock packet data
    static std::vector<u_char> mock_packet(64);
    for (size_t i = 0; i < mock_packet.size(); ++i) {
        mock_packet[i] = static_cast<u_char>(i % 256);
    }
    
    *pkt_data = mock_packet.data();
    
    return 1; // Success
}

int pcap_compile(pcap_t* p, struct bpf_program* fp, const char* str, int optimize, uint32_t netmask) {
    (void)optimize; // Suppress unused parameter warning
    (void)netmask; // Suppress unused parameter warning
    if (!p || !fp || !str) {
        return -1;
    }
    
    std::cout << "Mock pcap_compile: filter='" << str << "'" << std::endl;
    
    // Mock compilation - just set some values
    fp->bf_len = 1;
    fp->bf_insns = nullptr; // In real implementation, this would be allocated
    
    return 0;
}

void pcap_freecode(struct bpf_program* fp) {
    if (fp) {
        // Mock implementation - nothing to free
        std::cout << "Mock pcap_freecode called" << std::endl;
    }
}

int pcap_setfilter(pcap_t* p, struct bpf_program* fp) {
    if (!p || !fp) {
        return -1;
    }
    
    std::cout << "Mock pcap_setfilter: " << p->device_name << std::endl;
    return 0;
}

char* pcap_geterr(pcap_t* p) {
    (void)p; // Suppress unused parameter warning
    static char error_buffer[PCAP_ERRBUF_SIZE];
    strcpy(error_buffer, "Mock pcap error");
    return error_buffer;
}

int pcap_stats(pcap_t* p, struct pcap_stat* ps) {
    if (!p || !ps) {
        return -1;
    }
    
    // Return mock statistics
    ps->ps_recv = 1000 + mock_pcap_counter++;
    ps->ps_drop = 5;
    ps->ps_ifdrop = 2;
    
    return 0;
}

int pcap_setnonblock(pcap_t* p, int nonblock, char* errbuf) {
    (void)errbuf; // Suppress unused parameter warning
    if (!p) {
        return -1;
    }
    
    std::cout << "Mock pcap_setnonblock: " << p->device_name << " (nonblock=" << nonblock << ")" << std::endl;
    return 0;
}

int pcap_getnonblock(pcap_t* p, char* errbuf) {
    (void)errbuf; // Suppress unused parameter warning
    if (!p) {
        return -1;
    }
    
    return 0; // Mock: always blocking
}

int pcap_inject(pcap_t* p, const void* buf, size_t size) {
    if (!p || !buf) {
        return -1;
    }
    
    std::cout << "Mock pcap_inject: " << p->device_name << " (size=" << size << ")" << std::endl;
    return static_cast<int>(size);
}

int pcap_sendpacket(pcap_t* p, const u_char* buf, int size) {
    return pcap_inject(p, buf, size);
}

pcap_dumper_t* pcap_dump_open(pcap_t* p, const char* fname) {
    (void)p; // Suppress unused parameter warning
    auto* dumper = new pcap_dumper();
    dumper->filename = fname ? fname : "mock_dump.pcap";
    dumper->is_open = true;
    
    mock_dumper_handles.push_back(dumper);
    
    std::cout << "Mock pcap_dump_open: " << fname << std::endl;
    
    return dumper;
}

void pcap_dump(u_char* user, const struct pcap_pkthdr* h, const u_char* sp) {
    if (!user || !h || !sp) {
        return;
    }
    
    auto* dumper = reinterpret_cast<pcap_dumper_t*>(user);
    if (dumper && dumper->is_open) {
        std::cout << "Mock pcap_dump: " << dumper->filename 
                  << " (packet size=" << h->len << ")" << std::endl;
    }
}

void pcap_dump_close(pcap_dumper_t* p) {
    if (p) {
        p->is_open = false;
        std::cout << "Mock pcap_dump_close: " << p->filename << std::endl;
        
        // Remove from handles list
        auto it = std::find(mock_dumper_handles.begin(), mock_dumper_handles.end(), p);
        if (it != mock_dumper_handles.end()) {
            mock_dumper_handles.erase(it);
        }
        
        delete p;
    }
}

int pcap_dump_flush(pcap_dumper_t* p) {
    if (!p) {
        return -1;
    }
    
    std::cout << "Mock pcap_dump_flush: " << p->filename << std::endl;
    return 0;
}

int pcap_findalldevs(pcap_if_t** alldevsp, char* errbuf) {
    (void)errbuf; // Suppress unused parameter warning
    if (!alldevsp) {
        return -1;
    }
    
    // Create mock interfaces
    auto* dev1 = new pcap_if_t();
    dev1->name = strdup("eth0");
    dev1->description = strdup("Mock Ethernet Interface");
    dev1->addresses = nullptr;
    dev1->flags = PCAP_IF_UP | PCAP_IF_RUNNING;
    dev1->next = nullptr;
    
    auto* dev2 = new pcap_if_t();
    dev2->name = strdup("wlan0");
    dev2->description = strdup("Mock Wireless Interface");
    dev2->addresses = nullptr;
    dev2->flags = PCAP_IF_UP | PCAP_IF_RUNNING;
    dev2->next = dev1;
    
    auto* dev3 = new pcap_if_t();
    dev3->name = strdup("lo");
    dev3->description = strdup("Mock Loopback Interface");
    dev3->addresses = nullptr;
    dev3->flags = PCAP_IF_LOOPBACK | PCAP_IF_UP | PCAP_IF_RUNNING;
    dev3->next = dev2;
    
    *alldevsp = dev3;
    
    std::cout << "Mock pcap_findalldevs: found 3 interfaces" << std::endl;
    
    return 0;
}

void pcap_freealldevs(pcap_if_t* alldevsp) {
    while (alldevsp) {
        auto* next = alldevsp->next;
        free(alldevsp->name);
        free(alldevsp->description);
        delete alldevsp;
        alldevsp = next;
    }
    
    std::cout << "Mock pcap_freealldevs: freed all devices" << std::endl;
}

char* pcap_lookupdev(char* errbuf) {
    (void)errbuf; // Suppress unused parameter warning
    static char device_name[] = "eth0";
    std::cout << "Mock pcap_lookupdev: returning eth0" << std::endl;
    return device_name;
}

int pcap_lookupnet(const char* device, uint32_t* netp, uint32_t* maskp, char* errbuf) {
    (void)errbuf; // Suppress unused parameter warning
    if (!device || !netp || !maskp) {
        return -1;
    }
    
    // Mock network information
    *netp = 0xC0A80000;  // 192.168.0.0
    *maskp = 0xFFFFFF00; // 255.255.255.0
    
    std::cout << "Mock pcap_lookupnet: " << device << " -> 192.168.0.0/24" << std::endl;
    
    return 0;
}

int pcap_datalink(pcap_t* p) {
    if (!p) {
        return -1;
    }
    
    return DLT_EN10MB; // Ethernet
}

int pcap_snapshot(pcap_t* p) {
    if (!p) {
        return -1;
    }
    
    return p->snaplen;
}

int pcap_is_swapped(pcap_t* p) {
    if (!p) {
        return -1;
    }
    
    return 0; // Mock: not swapped
}

int pcap_major_version(pcap_t* p) {
    if (!p) {
        return -1;
    }
    
    return 1; // Mock version
}

int pcap_minor_version(pcap_t* p) {
    if (!p) {
        return -1;
    }
    
    return 0; // Mock version
}

FILE* pcap_file(pcap_t* p) {
    if (!p) {
        return nullptr;
    }
    
    return nullptr; // Mock: no file
}

int pcap_fileno(pcap_t* p) {
    if (!p) {
        return -1;
    }
    
    return -1; // Mock: no file descriptor
}

int pcap_dump_file(pcap_dumper_t* p) {
    if (!p) {
        return -1;
    }
    
    return -1; // Mock: no file descriptor
}

long pcap_ftell(pcap_t* p) {
    if (!p) {
        return -1;
    }
    
    return 0; // Mock: at beginning
}

int pcap_seek(pcap_t* p, long offset) {
    if (!p) {
        return -1;
    }
    
    std::cout << "Mock pcap_seek: " << p->device_name << " (offset=" << offset << ")" << std::endl;
    return 0;
}

int pcap_dump_ftell(pcap_dumper_t* p) {
    if (!p) {
        return -1;
    }
    
    return 0; // Mock: at beginning
}

int pcap_dump_ftell64(pcap_dumper_t* p) {
    return pcap_dump_ftell(p);
}

int64_t pcap_ftell64(pcap_t* p) {
    return pcap_ftell(p);
}

int pcap_seek64(pcap_t* p, int64_t offset) {
    return pcap_seek(p, static_cast<long>(offset));
}

int pcap_set_tstamp_precision(pcap_t* p, int tstamp_precision) {
    if (!p) {
        return -1;
    }
    
    std::cout << "Mock pcap_set_tstamp_precision: " << p->device_name 
              << " (precision=" << tstamp_precision << ")" << std::endl;
    return 0;
}

int pcap_get_tstamp_precision(pcap_t* p) {
    if (!p) {
        return -1;
    }
    
    return 0; // Mock: microsecond precision
}

int pcap_set_tstamp_type(pcap_t* p, int tstamp_type) {
    if (!p) {
        return -1;
    }
    
    std::cout << "Mock pcap_set_tstamp_type: " << p->device_name 
              << " (type=" << tstamp_type << ")" << std::endl;
    return 0;
}

int pcap_list_tstamp_types(pcap_t* p, int** tstamp_typesp) {
    if (!p || !tstamp_typesp) {
        return -1;
    }
    
    // Mock: return one timestamp type
    static int types[] = {0}; // PCAP_TSTAMP_HOST
    *tstamp_typesp = types;
    
    return 1;
}

void pcap_free_tstamp_types(int* tstamp_types) {
    (void)tstamp_types; // Suppress unused parameter warning
    // Mock: nothing to free
}

int pcap_tstamp_type_name_to_val(const char* name) {
    if (!name) {
        return -1;
    }
    
    if (strcmp(name, "host") == 0) {
        return 0; // PCAP_TSTAMP_HOST
    }
    
    return -1;
}

const char* pcap_tstamp_type_val_to_name(int tstamp_type) {
    if (tstamp_type == 0) {
        return "host";
    }
    
    return nullptr;
}

const char* pcap_tstamp_type_val_to_description(int tstamp_type) {
    if (tstamp_type == 0) {
        return "Host timestamp";
    }
    
    return nullptr;
}

int pcap_set_immediate_mode(pcap_t* p, int immediate) {
    if (!p) {
        return -1;
    }
    
    std::cout << "Mock pcap_set_immediate_mode: " << p->device_name 
              << " (immediate=" << immediate << ")" << std::endl;
    return 0;
}

int pcap_set_buffer_size(pcap_t* p, int buffer_size) {
    if (!p) {
        return -1;
    }
    
    std::cout << "Mock pcap_set_buffer_size: " << p->device_name 
              << " (size=" << buffer_size << ")" << std::endl;
    return 0;
}

int pcap_set_promisc(pcap_t* p, int promisc) {
    if (!p) {
        return -1;
    }
    
    p->is_promiscuous = promisc != 0;
    std::cout << "Mock pcap_set_promisc: " << p->device_name 
              << " (promisc=" << promisc << ")" << std::endl;
    return 0;
}

int pcap_set_rfmon(pcap_t* p, int rfmon) {
    if (!p) {
        return -1;
    }
    
    std::cout << "Mock pcap_set_rfmon: " << p->device_name 
              << " (rfmon=" << rfmon << ")" << std::endl;
    return 0;
}

int pcap_set_timeout(pcap_t* p, int timeout_ms) {
    if (!p) {
        return -1;
    }
    
    p->timeout_ms = timeout_ms;
    std::cout << "Mock pcap_set_timeout: " << p->device_name 
              << " (timeout=" << timeout_ms << "ms)" << std::endl;
    return 0;
}

int pcap_set_snaplen(pcap_t* p, int snaplen) {
    if (!p) {
        return -1;
    }
    
    p->snaplen = snaplen;
    std::cout << "Mock pcap_set_snaplen: " << p->device_name 
              << " (snaplen=" << snaplen << ")" << std::endl;
    return 0;
}

int pcap_activate(pcap_t* p) {
    if (!p) {
        return -1;
    }
    
    p->is_open = true;
    std::cout << "Mock pcap_activate: " << p->device_name << std::endl;
    return 0;
}

int pcap_list_datalinks(pcap_t* p, int** dlt_bufp) {
    if (!p || !dlt_bufp) {
        return -1;
    }
    
    // Mock: return one datalink type
    static int types[] = {DLT_EN10MB}; // Ethernet
    *dlt_bufp = types;
    
    return 1;
}

void pcap_free_datalinks(int* dlt_list) {
    (void)dlt_list; // Suppress unused parameter warning
    // Mock: nothing to free
}

int pcap_set_datalink(pcap_t* p, int dlt) {
    if (!p) {
        return -1;
    }
    
    std::cout << "Mock pcap_set_datalink: " << p->device_name 
              << " (dlt=" << dlt << ")" << std::endl;
    return 0;
}

int pcap_datalink_name_to_val(const char* name) {
    if (!name) {
        return -1;
    }
    
    if (strcmp(name, "EN10MB") == 0) {
        return DLT_EN10MB;
    }
    
    return -1;
}

const char* pcap_datalink_val_to_name(int dlt) {
    if (dlt == DLT_EN10MB) {
        return "EN10MB";
    }
    
    return nullptr;
}

const char* pcap_datalink_val_to_description(int dlt) {
    if (dlt == DLT_EN10MB) {
        return "Ethernet";
    }
    
    return nullptr;
}

} // extern "C"
