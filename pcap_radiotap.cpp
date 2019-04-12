#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <sstream>
#include "RadiotapScanner.h"

extern "C"{
    #include <pcap.h>
    #include <string.h>
    #include "radiotap_iter.h"
    #if defined(__APPLE__)
    #include <machine/endian.h>
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

  if(argc==1){
    RadiotapScanner *scanner;
    std::vector<std::string> arp;
    arp.push_back("70:4f:57:2e:2d:66");

    try{
      scanner = new RadiotapScanner(arp);
    }catch(std::invalid_argument& e){
      std::cout << "Catch " << std::endl;
      return 1;
    }
    scanner->startScan(5);
    WiFiResult* output=scanner->getWiFiResult();
    output->prettyprint();
    delete(output);
    scanner->close();
    delete(scanner);
  }

  else if(argc==2){
    printf("Due argomenti");
    std::vector<std::string> arp;
    arp.push_back("70:4f:57:2e:2d:66");
    RadiotapScanner *scanner2 = new RadiotapScanner(argv[1],arp);
  //  scanner2->startScan();
    std::unordered_map<std::string, Device*> r = scanner2->getResult();
    std::cout <<"\nStampa finale\n" << std::endl;
    for(auto i : r){
      std::cout << i.second->getDeviceMAC();
      printf(" Signal : %d ",(signed char) i.second->power.antenna_signal);
      printf(" Noise : %d\n",(signed char) i.second->power.antenna_noise);

    }
    for(auto i : r){
      if(i.second->isAP){
        std::cout << "******************************************" << std::endl;
          std::cout << "Main Device :" << i.second->main_device->mac_address;
          std::cout << " AP con Mac Address:" << i.second->mac_address << std::endl;
          std::cout << "SSID:" << i.second->ssid << std::endl;
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
        }
        else{
          std::cout << "Non trovato" << std::endl;
        }
        std::cout << std::endl;
      }

      std::cout << "Endpoint per " << std::endl;
      for(unsigned long c = 0 ; c < i.second->end_point.size() ; c++){
        std::cout << i.second->end_point[c] << std::endl;
      }
      std::cout << "Entrypoint per " << std::endl;
      for(unsigned long c = 0 ; c < i.second->start_point.size() ; c++){
        std::cout << i.second->start_point[c] << std::endl;
      }

      std::cout << "******************************************" << std::endl;
      }
  }
  for(auto i : r){
    if(!i.second->isAP){
      std::cout << "Device " << i.second->getDeviceMAC() << std::endl;
      signal_power p =i.second->returnPowerValues();
      printf("\tSignal : %d\n",(signed char) i.second->power.antenna_signal);
      printf("\tNoise : %d\n",(signed char) i.second->power.antenna_noise);
      std::cout << "Comunica con " << std::endl;
      for(unsigned long c = 0 ; c < i.second->talkers.size() ; c++){
        std::cout << i.second->talkers[c] << std::endl;
      }
    }
    std::cout << "*********************" << std::endl;
  }

  WiFiResult* output=scanner2->getWiFiResult();
  output->prettyprint();
  delete(output);
  scanner2->close();
  delete(scanner2);
}
}
