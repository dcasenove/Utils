#include "WiFiResult.h"
#include <iostream>

WiFiResult::WiFiResult(std::list<device_wifi> input_devices,std::list<pc_wifi> input_pcs){
  devices_wifi=input_devices;
  pcs_wifi=input_pcs;
}

std::list<pc_wifi> WiFiResult::getPCS(){
  return pcs_wifi;
}
std::list<device_wifi> WiFiResult::getDevices(){
  return devices_wifi;
}

void WiFiResult::prettyprint(){
  std::cout << "Stampa dei device WiFi" << std::endl;
  for(auto n : devices_wifi){
    std::cout << "MAC Address: " << n.mac_wifidevice << " SSID: " << n.ssid << " Channel : " << n.channel;
    printf(" Signal : %d ",(signed char) n.antenna_signal);
    printf(" Noise : %d\n",(signed char) n.antenna_noise);
    std::cout << "Device connessi:" << std::endl;
    std::list<connected_device>::iterator it;
    for (it=n.connected.begin(); it != n.connected.end(); ++it){
      std::cout << it->mac_pc;
      if(it->isDirectlyConnected){
        std::cout <<" *";
      }
    std::cout << '\n';
  }
}

  for(auto n : pcs_wifi){
    std::cout << "MAC Address: " << n.mac_pc << " connesso a device MAC Address: " << n.mac_wifidevice;
    if(n.antenna_noise!=0 && n.antenna_signal!=0){
      printf(" Signal : %d ",(signed char) n.antenna_signal);
      printf(" Noise : %d\n",(signed char) n.antenna_noise);
    }
    else{
      std::cout << " tramite ethernet" << std::endl;
    }
  }
}
