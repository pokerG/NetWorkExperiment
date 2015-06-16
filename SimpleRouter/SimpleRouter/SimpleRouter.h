#pragma once

#include "resource.h"

#include "protocol.h"
#include "pcap.h"

string IPntoa(ULONG nIPAddr); //IP address transform
string MACntoa(UCHAR *nMACAddr); //MAC address transform
bool cmpMAC(UCHAR *MAC1, UCHAR *MAC2);
void cpyMAC(UCHAR *MAC1, UCHAR *MAC2); // MAC2 copy to MAC1
void setMAC(UCHAR *MAC, UCHAR ch);
bool IPQuery(ULONG IPaddr, UCHAR *p); //IP address Query
UINT Capture(PVOID pParam); //data packet capture
UINT CaptureLocalARP(PVOID pParam); //capture the local interface's MAC address
void ARPRequest(pcap_t *adhandle, UCHAR *srcMAC, ULONG srcIP, ULONG targetIP);//Send ARP Request
DWORD RouteQuery(UINT &ifNo, DWORD desIP, CList <RouteTable_t, RouteTable_t&> *routeTable);//Router Table Query
void ARPPacketProc(struct pcap_pkthdr *header, const u_char *pkt_data);//process ARP
void IPPacketProc(IfInfo_t *pIfInfo, struct pcap_pkthdr *header, const u_char *pkt_data);//process IP
void ICMPPacketProc(IfInfo_t *pIfInfo, BYTE typp, BYTE code, const u_char *pktdata);//process ICMP
bool IsChecksum(char *buffer);//the Checksum is right?
USHORT ChecksumCompute(USHORT *buffer, int size);//Compute Checksum
void Logprint(string str); //print log
void CALLBACK OnTimer(HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime);