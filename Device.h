#include <string>
#include <vector>

class Device{
    public:
        bool isAP;
        char *ssid;
        std::string mac_address;
        std::vector<std::string> talkers;

        Device(std::string mac);
        void setAP(u_int8_t ,char * ssid);
        void Print();
        std::string getDeviceMAC();
        char *getDeviceSSID();
        bool isTalking(std::string dev_mac);
        void addTalker(std::string dev_mac);
};
