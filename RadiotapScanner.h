#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <sstream>
#include "Device.h"

extern "C"{
    #include <pcap.h>
    #include <string.h>
    #include "radiotap_iter.h"
    #include <machine/endian.h>
    #if defined(__APPLE__)
    #else
    #include <endian.h>
    #endif
}

std::unordered_map<std::string,Device*> devices;


#define NPACKETS 10
#define SIZERADIOTAP 25
#define SIZEBEACONFRAME 4
//Frequency

typedef struct freq_cvt_s {
    unsigned int fmin;         /* Frequenza mimina in MHz */
    unsigned  fmax;            /* Frequenza massima in MHz */
    int cmin;                  /* Base channel minimo */
    bool is_bg;                /* B/G channel */
} freq_cvt_t;

#define FREQ_STEP 5     

static freq_cvt_t freq_cvt[] = {
    { 2412, 2472,   1, true },
    { 2484, 2484,  14, true },
    { 5000, 5995,   0, false },
    { 4910, 4980, 182, false }
};

#define NUM_FREQ_CVT (sizeof(freq_cvt) / sizeof(freq_cvt_t))
#define MAX_CHANNEL(fc) ( (gint) ((fc.fmax - fc.fmin) / FREQ_STEP) + fc.cmin )

//
//
struct mac_addr {
   u_int8_t bytes[6];
};
struct isAP{
    struct mac_addr addr;
    char ssid[32];
};


struct ieee80211mac {
    //unsigned int
    u_int16_t framectl;
    u_int16_t duration;
 /*   u_int8_t  receiver[6];
    u_int8_t  transmitter[6];
    u_int8_t  destination[6];
    u_int16_t seq_control;*/
};

struct framectl_bits{
    unsigned short protocol_version:2;
    unsigned short type:2;
    unsigned short subtype:4;
    unsigned short to_ds:1;
    unsigned short from_ds:1;
    unsigned short more_frag:1;
    unsigned short retry:1;
    unsigned short pwr_mngmt:1;
    unsigned short more_data:1;
    unsigned short prot_frame:1;
    unsigned short order:1;
};

struct beacon_frame{
    u_int16_t framectl;
    u_int16_t duration;
    u_int8_t  receiver[6];
    u_int8_t  transmitter[6];
    u_int8_t  destination[6]; //SSID
    u_int16_t seq_control;
    u_int64_t timestamp;
    u_int16_t beacon_interval;
    u_int16_t capability_info;
    u_int8_t  tag;
    u_int8_t  length;
    char ssid[32];
};

//Ignora tutti i tipi di flag dei control frames
struct control_frames{
    u_int16_t framectl;
    u_int16_t duration;
    u_int8_t receiver[6];
    u_int8_t transmitter[6];
    //u_int16_t blockack_control; //Bitmap
    //Variable BA information
    //4 - FCS
};


struct data_frames{
    u_int16_t framectl;
    u_int16_t duration;
    u_int8_t receiver[6];
    u_int8_t transmitter[6];
    u_int8_t destination[6];
};

char filter[]="type mgt or type ctl or type data";

//Acknowledgment e Clear-to-send non parsato perche' non contiene source
//QoS Data
//QoS Data null
//

static int fcshdr = 0;

static const struct radiotap_align_size align_size_000000_00[] = {
	[0] = { .align = 1, .size = 4, },
	[52] = { .align = 1, .size = 4, },
};

static const struct ieee80211_radiotap_namespace vns_array[] = {
	{
		.oui = 0x000000,
		.subns = 0,
		.n_bits = sizeof(align_size_000000_00),
		.align_size = align_size_000000_00,
	},
};

static const struct ieee80211_radiotap_vendor_namespaces vns = {
	.ns = vns_array,
	.n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
};

class RadiotapScanner{
  public:
    char *device, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    //char filter[]="type mgt or type ctl or type data";
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 network;
    RadiotapScanner();
    RadiotapScanner(char *arg);
    void startScan();
    void close();
};
