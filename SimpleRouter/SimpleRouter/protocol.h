#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#define MAX_INTERFACE 5 //the max size of interface

#pragma pack(1)
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <list>
#include "pcap.h"
using namespace std;
//some Protocol and Router Struct
struct FrameHeader_t{
	UCHAR DesMAC[6];
	UCHAR SrcMAC[6];
	USHORT FrameType;
};

struct ARPFrame_t{
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HALen; //Hardware address length
	BYTE ProLen; //Protocal length
	WORD Operation;
	UCHAR SrcHA[6];
	ULONG SrcIP;
	UCHAR DesHA[6];
	ULONG DesIP;
};

struct IPHeader_t{
	BYTE Ver_HLen; //Version and Header length
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Seg; //flag and segment
	BYTE TTL;
	BYTE UpProtocol;
	WORD Checksum;
	ULONG SrcIP;
	ULONG DesIP;
};

struct ICMPHeader_t{
	BYTE Type;
	BYTE Code;
	WORD Checksum;
	WORD ID;
	WORD Sequence;
};

struct IPFrame_t{
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
};

struct IP_t{
	ULONG IPAddr;
	ULONG IPMask;
};

struct IfInfo_t{ //Interface info
	string DeviceName;
	string Description;
	UCHAR MACAddr[6];
	vector<IP_t> IP;
	pcap_t *adhandle;
};

struct SendPacket_t{
	int len;
	BYTE PktData[2000];
	ULONG TargetIP;
	UINT_PTR n_mTimer; //Timer
	UINT IfNo; //the number of interface
};

struct RouteTable_t{
	ULONG Mask;
	ULONG DesIP;
	ULONG NextHop;
	UINT IfNo;
};

struct IP_MAC_t{ //the mapping of IP and MAC
	ULONG IPAddr;
	UCHAR MACAddr[6];
};

//Global Variable 
extern IfInfo_t IfInfo[MAX_INTERFACE];
extern int IfCount;  //the size of interface
extern UINT_PTR TimerCount;
extern list<SendPacket_t> SP; //the buffer queue of SendPacket
extern list<IP_MAC_t> IP_MAC; //the list of IP_MAC mapping
extern list<RouteTable_t> RouteTable;
//CMutex mMutex(0, 0, 0);
extern HANDLE mMutex;


#endif