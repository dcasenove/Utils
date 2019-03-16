#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <sstream>
#include "ArpScanner.h"
#include "RadiotapScanner.h"
#include "Pinger.h"

extern "C"{
    #include <pcap.h>
    #include <string.h>
    #include "radiotap_iter.h"
    #include <machine/endian.h>
    #if defined(__APPLE__)
    #else
    #include <endian.h>
    #endif
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <err.h>
    #include <dnet.h>

}

int main(int argc, char *argv[]){

  //  char *device, errbuf[PCAP_ERRBUF_SIZE];
  //  pcap_t *handle;
    //char filter[]="type mgt subtype beacon";
    //char filter[] = "type data";
  //  char filter[]="type mgt or type ctl or type data";
  //  struct bpf_program fp;

  //  bpf_u_int32 mask;
  //  bpf_u_int32 network;

  if(argc==1){
  /*  RadiotapScanner *scanner = new RadiotapScanner();
    scanner->startScan();
    scanner->close();*/
    ArpScanner *scanner = new ArpScanner();
    scanner->startScan();
    std::unordered_map<std::string,std::string> risultato;
    risultato=scanner->getResults();
    std::cout << "Stampo risultati arp scan" << std::endl;
    for (auto i : risultato){
      std::cout << "MAC : " << i.first << " IP : "<< i.second << std::endl;
    }
    //std::cout << "Ping 8.8.8.8" << std::endl;
    //Pinger *pinger = new Pinger();
    //pinger->startPing("8.8.8.8");
    //pinger->Destroy();
  }

  else if(argc==2){
    printf("Due argomenti");
  /*  ArpScanner *scanner = new ArpScanner();
    scanner->startScan();
    std::unordered_map<std::string,std::string> risultato;
    risultato=scanner->getResults();
    RadiotapScanner *scanner2 = new RadiotapScanner(argv[1]);
    std::unordered_map<std::string, Device*> r = scanner2->getResult();
    std::cout << "Test arp + radiotap" << std::endl;
    for(auto i : r){
      auto search = risultato.find(i.first);
      if(search != risultato.end()){
              i.second->Print();
        }
    }*/
    RadiotapScanner *scanner2 = new RadiotapScanner(argv[1]);
  //  scanner2->startScan();
    std::unordered_map<std::string, Device*> r = scanner2->getResult();
    std::cout <<"\nStampa finale\n" << std::endl;
    for(auto i : r){
      i.second->Print();
    }

    return 0;
  }
  else{
    return 1;
  }
}
