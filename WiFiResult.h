#include <string>
#include <list>

struct pc_wifi{
  std::string mac_pc;
  std::string mac_wifidevice;
  u_int8_t antenna_signal;
  u_int8_t antenna_noise;
};

struct device_wifi{
  std::string mac_wifidevice;
  std::string ssid;
  u_int8_t antenna_signal;
  u_int8_t antenna_noise;
  int channel;
  std::list<std::string> connected;
};

class WiFiResult{
  public:
    std::list<pc_wifi> pcs_wifi;
    std::list<device_wifi> devices_wifi;

    WiFiResult(std::list<device_wifi> input_devices,std::list<pc_wifi> input_pcs);
    std::list<pc_wifi> getPCS();
    std::list<device_wifi> getDevices();
    void prettyprint();
};
