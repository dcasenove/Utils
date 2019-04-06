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
      if(i.second->isAP){
        std::cout << "******************************************" << std::endl;
          std::cout << "Main Device :" << i.second->main_device->mac_address;
          std::cout << " AP con Mac Address:" << i.second->mac_address << std::endl;
          std::cout << "SSID:" << i.second->ssid << std::endl;
          //std::cout << "Power segment - Signal : " << power.antenna_signal << "Noise : " << power.antenna_noise << "Timestamp: " << power.timestamp;
          printf("\tSignal : %d\n",(signed char) i.second->power.antenna_signal);
          printf("\tNoise : %d\n",(signed char) i.second->power.antenna_noise);
          printf("\tChannel : %d\n", i.second->power.channel);

      std::cout << "Sto parlando con : " << std::endl;
      for(unsigned long c = 0 ; c < i.second->talkers.size() ; c++){
        std::cout << i.second->talkers[c];
        auto search = r.find(i.second->talkers[c]);
        if(search!=r.end()){
          if(search->second->isLocallyAdministered){
            std::cout << " Sono locale";
            if(search->second->main_device!=NULL){
            std::cout << " globally administered : "<< search->second->main_device->mac_address;
          }
          }
          else if(search->second->main_device!=NULL){
            std::cout << "Main device : " << search->second->main_device->mac_address;
          }
          //else if(search->second->main_device->getDeviceMAC()!=search->second->mac_address){
        //    std::cout << "Main device : " << search->second->main_device->mac_address;
        //  }
        }
        else{
          std::cout << "Non trovato" << std::endl;
        }
        std::cout << std::endl;
    /*
        auto search = devices.find(talkers[i]);
        if(search != devices.end()){
          struct signal_power toprint = search->second->returnPowerValues();
          printf(" che ha signal : %d\t",(signed char) toprint.antenna_signal);
          printf(" e noise : %d\n",(signed char) toprint.antenna_noise);
        }
        else{
          std::cout << "Non trovato";
        }*/
      }
      std::cout << "******************************************" << std::endl;

      }
  }
  scanner2->close();
  delete(scanner2);
}
}
