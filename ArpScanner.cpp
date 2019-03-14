#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <sstream>
#include "ArpScanner.h"

void pcap_cb(u_char *u, const struct pcap_pkthdr *hdr, const u_char *pkt){
  struct ether_arp *ether_arp;
  char eth_str[19];
  char ip_str[17];
  uint32_t ip;

  ether_arp = (struct ether_arp *)(pkt + sizeof(struct eth_hdr));

  /*Controlla solo risposte ARP*/
  if (ether_arp->arp_hdr.ar_op != ntohs(ARP_OP_REPLY))
    return;

  /*Scarta risposte out of range*/
  ip = *(uint32_t *)ether_arp->arp_ethip.ar_spa;
  ip = ntohl(ip);
  if (ip < ip_lo || ip > ip_hi){
        std::cout<< "Fuori range" << std::endl;
        return;
  }

  std::cout << "Prima di sprintf" << std::endl;
  snprintf((char *)eth_str,(size_t) sizeof(eth_str) - 1, "%02x:%02x:%02x:%02x:%02x:%02x",
      ether_arp->arp_ethip.ar_sha[0], ether_arp->arp_ethip.ar_sha[1],
      ether_arp->arp_ethip.ar_sha[2], ether_arp->arp_ethip.ar_sha[3],
      ether_arp->arp_ethip.ar_sha[4], ether_arp->arp_ethip.ar_sha[5]);

  snprintf((char *)ip_str,(size_t) sizeof(ip_str) - 1, "%d.%d.%d.%d",
      ether_arp->arp_ethip.ar_spa[0], ether_arp->arp_ethip.ar_spa[1],
      ether_arp->arp_ethip.ar_spa[2], ether_arp->arp_ethip.ar_spa[3]);

  printf("%-15s e' a %s\n", ip_str, eth_str);

  std::string mac;
  mac.assign(eth_str);
  std::string ip_given;
  ip_given.assign(ip_str);
  std::cout << "Prova MAC " << mac << "Prova IP " << ip_given << std::endl;
  auto search = devices_found.find(mac);
  if(search==devices_found.end()){
    devices_found.insert({mac,ip_given});
  }
}

  //Implementare fallimenti costruttore

ArpScanner::ArpScanner(){
  device = pcap_lookupdev(errbuf);
  if(device == NULL){
      std::cout << ("Device di rete non trovato per arp scan") << std::endl;
  //      return 1;
  }
  std::cout << ("Device di rete scelto per arp scan : ") << device << std::endl;

  if(pcap_lookupnet(device, &subnet, &netmask, errbuf) == -1) {
      std::cout << ("Errore netmask del device") << device << std::endl;
 //       return 1;
      subnet = 0;
      netmask = 0;
  }
  std::cout << "Subnet : " << subnet << "Netmask : " << netmask << std::endl;
  subnet=htonl(subnet);
  netmask=htonl(netmask);
  ip_lo = subnet & netmask;
  ip_hi = subnet + ~netmask;
  ip_lo++;
  ip_hi--;
  dnet_eth = init_dnet(device);
  if(dnet_eth == NULL){
      std::cout << "eth_open " << device << " fallita" << std::endl;
     // return 1;
  }
  handle = init_pcap(device);
}

eth_t * ArpScanner::init_dnet(char *device){
  intf_t *dnet_if;
  struct intf_entry entry;
  dnet_if = intf_open();
  memset(&entry, 0, sizeof(entry));
  strncpy(entry.intf_name, device, INTF_NAME_LEN - 1);
  intf_get(dnet_if, &entry);
  memcpy(&my_ipaddr, &entry.intf_addr.addr_ip, sizeof(my_ipaddr));
  memcpy(&my_ethaddr, &entry.intf_link_addr.addr_eth,sizeof(my_ethaddr));
  intf_close(dnet_if);
  return eth_open(device);
}

pcap_t * ArpScanner::init_pcap(char *device){
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program bpf;
  pcap_t *pcap;
  //int flags;
  char filter[1024];

    //Provare con 5ms la openlive e 128 snapshot
  pcap = pcap_open_live(device,64,1,1,errbuf);
  if(pcap == NULL){
      std::cout << ("Fallimento pcap_open_live");
      return NULL;
  }
    //Stampa debug di chi sono
  snprintf(filter, sizeof(filter),
    "arp and ether dst %02x:%02x:%02x:%02x:%02x:%02x",
  	my_ethaddr[0], my_ethaddr[1], my_ethaddr[2],
  	my_ethaddr[3], my_ethaddr[4], my_ethaddr[5]);

  if(pcap_compile(pcap, &bpf, filter, 1, 0) < 0){
  	pcap_close(pcap);
    std::cout << "Errore compilazione filtro " << std::endl;
  }
  if(pcap_setfilter(pcap, &bpf) < 0) {
  	pcap_close(pcap);
    std::cout << "Errore set filtro" << std::endl;
  }
  //Controllare se funzione cosi il setnonblock
  pcap_setnonblock(pcap,1,errbuf);
  return(pcap);
}

void ArpScanner::send_arp(eth_t *eth, uint32_t ip){
  u_char pkt[sizeof(struct eth_hdr) + sizeof(struct ether_arp)];
  //struct eth_hdr *ether;
  struct ether_arp *arp;
  //char *buf;
  //int rc;

  memset(pkt, 0, sizeof(pkt));
  memcpy(pkt, &eth_header, sizeof(eth_header));

  arp = (struct ether_arp *)(pkt + sizeof(struct eth_hdr));
  arp->arp_hdr.ar_hrd = htons(ARP_HRD_ETH);
  arp->arp_hdr.ar_pro = htons(ETH_TYPE_IP);
  arp->arp_hdr.ar_hln = ETH_ADDR_LEN;
  arp->arp_hdr.ar_pln = sizeof(ip);
  arp->arp_hdr.ar_op = htons(ARP_OP_REQUEST);

  memcpy(&arp->arp_ethip.ar_sha, &eth_header.eth_src,
  	  sizeof(eth_header.eth_src));
  memcpy(&arp->arp_ethip.ar_spa, &my_ipaddr, sizeof(my_ipaddr));
  memcpy(&arp->arp_ethip.ar_tpa, &ip, sizeof(ip));

  eth_send(eth, (void *)pkt, sizeof(pkt));
  }

void ArpScanner::startScan(){
  memset(&eth_header.eth_dst, 0xff, sizeof(eth_header.eth_dst));
  memcpy(&eth_header.eth_src, my_ethaddr, sizeof(my_ethaddr));
  eth_header.eth_type = htons(ETH_TYPE_ARP);
    for(int run = 0; run< 2 ; run++){
      cur_ip=ip_lo;
      std::cout << "Ip minimo" << ip_lo << "Ip max" << ip_hi << std::endl;
      do{
          std::cout << " Mando arp a " << (cur_ip) << std::endl;
          send_arp(dnet_eth, ntohl(cur_ip));
           // void (ArpScanner::*func)(u_char *, const struct pcap_pkthdr*, const u_char *);
           // func = &ArpScanner::pcap_cb;
          pcap_dispatch(handle, -1, pcap_cb, NULL);
          cur_ip++;
      }while (ntohl(cur_ip) <= ntohl(ip_hi));
      for (i = 0; i < 5; i++) {
        int x = 1;
        while (x > 0) {
          x = pcap_dispatch(handle, -1, /*(void *)*/pcap_cb, NULL);
        }
        std::cout << "Aspetto" << std::endl;
        sleep(1);
      }
    }
}

std::unordered_map<std::string,std::string> ArpScanner::getResults(){
  return devices_found;
}

void ArpScanner::close(){
  eth_close(dnet_eth);
  pcap_close(handle);
}
