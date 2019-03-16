#include <string>
#include <vector>
#include <unordered_map>
struct signal_power{
  time_t timestamp;
  int channel;
  u_int8_t antenna_signal;
  u_int8_t antenna_noise;
};


class Device{
    public:
        bool isAP;
        char *ssid;
        std::string mac_address;
        std::string ip_address;
        std::vector<std::string> talkers;
        struct signal_power power;

        Device(std::string mac);
        void setAP(u_int8_t ,char * ssid);
        void setIP(std::string ip);
        void Print();
        std::string getDeviceMAC();
        char *getDeviceSSID();
        std::string getDeviceIP();
        bool isTalking(std::string dev_mac);
        void addTalker(std::string dev_mac);
        void removeTalker(std::string dev_mac);
        void addPowerValues(struct signal_power p);
        signal_power returnPowerValues();
};

//Mossa da RadiotapScanner.h
std::unordered_map<std::string,Device*> devices;
