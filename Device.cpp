#include "Device.h"
#include <iostream>

Device::Device(std::string mac){
    isAP=false;
    mac_address=mac;
}

void Device::setAP(u_int8_t length, char *ssidp){
    isAP=true;
    ssid = new char[length];
    memcpy(ssid,ssidp,length);
}

void Device::Print(){
    std::cout << "Mac Address:" << mac_address << std::endl;
    if(isAP){
        std::cout << "SSID:" << ssid << std::endl;
    }
    std::cout << "Sto parlando con : " << std::endl;
    for(unsigned long i = 0 ; i < talkers.size() ; i++){
      std::cout << talkers[i] << std::endl;
    }
}

std::string Device::getDeviceMAC(){
    return mac_address;
}

char * Device::getDeviceSSID(){
    return ssid;
}

bool Device::isTalking(std::string dev_mac){
    std::cout << "Dentro istalking";
    for(unsigned long i=0; i < talkers.size() ; i++){
        if(talkers[i]==dev_mac){
            return true;
        }
    }
    return false;
}

void Device::addTalker(std::string dev_mac){
    std::cout << "Dentro addtalker";
    talkers.push_back(dev_mac);
}
