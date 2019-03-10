extern "C"{
  #include <pcap.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <err.h>
  #include <dnet.h>
}

struct ether_arp {
	struct arp_hdr arp_hdr;
	struct arp_ethip arp_ethip;
};

struct eth_hdr eth_header;


uint32_t my_ipaddr;
uint8_t my_ethaddr[6];

uint32_t ip_lo;
uint32_t ip_hi;

void pcap_cb(u_char *u, const struct pcap_pkthdr *hdr, const u_char *pkt);

class ArpScanner{
  public:
    char *device, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    eth_t *dnet_eth;

    u_int32_t subnet;
    u_int32_t netmask;
    uint32_t cur_ip;
    int i;

    ArpScanner();
    eth_t * init_dnet(char *device);
    pcap_t * init_pcap(char *device);
    void send_arp(eth_t *eth, uint32_t ip);
    void startScan();
    void close();

};
