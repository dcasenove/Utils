#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <sstream>
#include <cstring>
#include <bitset>

struct signal_power{
  time_t timestamp;
  int channel;
  u_int8_t antenna_signal;
  u_int8_t antenna_noise;
};

bool checkLocalAdministered(std::string mac){
  std::string octect1 = mac.substr(0,2);
  std::stringstream ss;
  ss << std::hex << octect1;
  unsigned np;
  ss >> np;
  std::bitset<8> b(np);
//  cout << b.to_string() << endl;
  std::string finale = b.to_string();
  std::cout << "Prima " << finale << std::endl;
  if(finale.compare(6,1,"0")==0){
    std::cout << "Globally administered" << std::endl;
    return false;
  }
  else if(finale.compare(6,1,"1")==0){
    std::cout << "Locally Administered" << std::endl;
    return true;
  }
  return false;
}


class Device{
    public:
        bool isAP;
        bool isLocallyAdministered;
        std::string ssid;
        std::string mac_address;
        std::string ip_address;
        std::vector<std::string> talkers;
        //Aggiunta end_point start_point
        std::vector<std::string> end_point;
        std::vector<std::string> start_point;
        std::vector<Device*> local_assigned_interfaces;
        Device* main_device;
        struct signal_power power;

        Device(std::string mac);
        ~Device();
        void setAP(std::string ssid);
        void setIP(std::string ip);
        void Print();
        std::string getDeviceMAC();
        std::string getDeviceSSID();
        std::string getDeviceIP();
        bool isTalking(std::string dev_mac);
        void addTalker(std::string dev_mac);
        void removeTalker(std::string dev_mac);
        void addEndPoint(std::string dev_mac);
        void removeEndPoint(std::string dev_mac);
        void addStartPoint(std::string dev_mac);
        void removeStartPoint(std::string dev_mac);
        void addPowerValues(struct signal_power p);
        void addLocalInterface(Device* d);
        signal_power returnPowerValues();
};
