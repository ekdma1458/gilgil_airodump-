#ifndef AIRODUMP_H
#define AIRODUMP_H
#include "stdafx.h"

typedef struct ST_JE_802_HEADER{
    int16_t     FC;
    int16_t     DUR;
    uint8_t      rec[6];
    uint8_t      trs[6];
    uint8_t      bssid[6];
    int16_t     seq;
}st_je_802_header;

typedef struct ST_JE_AP_DUMP_HEADER {
    uint8_t     bssid[6];
    int8_t      pwr;
    uint32_t    beacons;
    uint32_t    data;
    uint8_t     ch;
    uint8_t     enc;
    uint16_t    enc_version;
    string      essid;
}st_je_ap_header;

void usage();
void dump(unsigned char* buf, int size);
//void printApDump(map<ID, st_je_ap_header> ap_info);
//void printApToStaion(map<pair<ID, ID>, uint64_t> ip_a_to_b);
void printID(string id);

#endif // AIRODUMP_H
