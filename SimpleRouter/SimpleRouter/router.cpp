#include "stdafx.h"
#include "protocol.h"
#include "router.h"
#include <ctime>
#include <cstdio>
#include <iostream>
using namespace std;

void Logprint(string str){
	time_t tt = time(NULL);
	tm* t = localtime(&tt);
	printf("%d-%02d-%02d %02d:%02d:%02d     ",
		t->tm_year + 1900,
		t->tm_mon + 1,
		t->tm_mday,
		t->tm_hour,
		t->tm_min,
		t->tm_sec);
	cout << str << endl;
}

void setMAC(UCHAR *MAC, UCHAR ch){
	for (int i = 0; i < 6; i++){
		MAC[i] = ch;
	}
	return;
}

void cpyMAC(UCHAR *MAC1, UCHAR *MAC2){
	for (int i = 0; i < 6; i++){
		MAC1[i] = MAC2[i];
	}
}

bool cmpMAC(UCHAR *MAC1, UCHAR *MAC2){
	for (int i = 0; i < 6; i++){
		if (MAC1[i] != MAC2[i]) return false;
	}
	return true;
}


string IPntoa(ULONG nIPAddr){
	char strbuf[50];
	u_char *p;
	string str;
	p = (u_char*)&nIPAddr;
	sprintf(strbuf, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	str = strbuf;
	return str;
}

string MACntoa(UCHAR *nMACAddr){
	char strbuf[50];
	string str;
	sprintf(strbuf, "%02X:%02X:%02X:%02X:%02X:%02X", nMACAddr[0], nMACAddr[1], nMACAddr[2], nMACAddr[3], nMACAddr[4], nMACAddr[5]);
	str = strbuf;
	return str;
}

bool IsChecksum(char *buffer){
	IPHeader_t * ip_header = (IPHeader_t *)buffer;

	unsigned short check_buff[sizeof(IPHeader_t)];
	unsigned short checksumBuf = ip_header->Checksum;

	ip_header->Checksum = 0;

	memset(check_buff, 0, sizeof(IPHeader_t));
	memcpy(check_buff, ip_header, sizeof(IPHeader_t));
	ip_header->Checksum = ChecksumCompute(check_buff, sizeof(IPHeader_t));
	if (ip_header->Checksum == checksumBuf){
		return true;
	}
	else{
		return false;
	}
	/*if (ChecksumCompute(check_buff, sizeof(IPHeader_t)) != 0){
	return false;
	}
	else{
	return true;
	}*/
}

void ARPRequest(pcap_t *adhandle, UCHAR *srcMAC, ULONG srcIP, ULONG targetIP){
	ARPFrame_t ARPFrame;

	for (int i = 0; i < 6; i++){
		ARPFrame.FrameHeader.DesMAC[i] = 255;
		ARPFrame.FrameHeader.SrcMAC[i] = srcMAC[i];
		ARPFrame.SrcHA[i] = srcMAC[i];
		ARPFrame.DesHA[i] = 0;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806); //ARP
	ARPFrame.HardwareType = htons(0x0001); //Ethernet
	ARPFrame.ProtocolType = htons(0x0800); //IP Address
	ARPFrame.HALen = 6;
	ARPFrame.ProLen = 4;
	ARPFrame.Operation = htons(0x0001);//ARP Request
	ARPFrame.SrcIP = srcIP;
	ARPFrame.DesIP = targetIP;
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0){
		fprintf(stderr, "Error sending ARP Request: %s\n", pcap_geterr(adhandle));
	}
}

UINT Capture(PVOID pParam){
	int res;
	IfInfo_t *pIfInfo;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	pIfInfo = (IfInfo_t *)pParam;
	while (true){
		res = pcap_next_ex(pIfInfo->adhandle, &header, &pkt_data);
		if (res == 1){
			FrameHeader_t *fh;
			fh = (FrameHeader_t *)pkt_data;
			switch (ntohs(fh->FrameType)){
			case 0x0806:
				ARPFrame_t *ARPf;
				ARPf = (ARPFrame_t *)pkt_data;
				ARPPacketProc(header, pkt_data);
				break;
			case 0x0800:
				IPFrame_t *IPf;
				IPf = (IPFrame_t *)pkt_data;
				IPPacketProc(pIfInfo, header, pkt_data);
				break;
			default:
				break;
			}
		}
		else if (!res) { continue; }
		else { fprintf(stderr, "Error reading data packet: %s\n", pcap_geterr(pIfInfo->adhandle)); }

	}
	return 0;
}




UINT WINAPI CaptureLocalARP(PVOID pParam)
{
	int res;
	pcap_pkthdr *header;
	const u_char *pkt_data;
	IfInfo_t *pIfInfo;
	ARPFrame_t *ARPFrame;

	pIfInfo = (IfInfo_t *)pParam;

	while (true){
		Sleep(50);
		res = pcap_next_ex(pIfInfo->adhandle, &header, &pkt_data);
		if (!res) continue;
		if (res > 0){
			ARPFrame = (ARPFrame_t*)(pkt_data);
			if ((ARPFrame->FrameHeader.FrameType == htons(0x0806)) &&
				(ARPFrame->Operation == htons(0x0002)) &&
				(ARPFrame->SrcIP == pIfInfo->IP[1].IPAddr)){
				cpyMAC(pIfInfo->MACAddr, ARPFrame->SrcHA);
				return 0;

			}
		}
	}
}

void ARPPacketProc(struct pcap_pkthdr *header, const u_char *pkt_data){
	bool flag;
	ARPFrame_t ARPFrame;
	IPFrame_t *IPFrame;
	SendPacket_t sPacket;
	IP_MAC_t ip_mac;
	UCHAR macAddr[6];
	ARPFrame = *(ARPFrame_t *)pkt_data;
	if (ARPFrame.Operation == ntohs(0x0002)){
		Logprint("Receive ARP Response");
		Logprint("ARP " + (IPntoa(ARPFrame.SrcIP)) + " -- " + MACntoa(ARPFrame.SrcHA));
		if (IPQuery(ARPFrame.SrcIP, macAddr)){
			Logprint("this correspondence existed in IP-MAC Mapping");
			return;
		}
		else{
			ip_mac.IPAddr = ARPFrame.SrcIP;
			memcpy(ip_mac.MACAddr, ARPFrame.SrcHA, 6);
			IP_MAC.push_front(ip_mac);
			Logprint("this correspondence insert to IP-MAC Mapping");
		}
		WaitForSingleObject(mMutex, INFINITE);
		do{
			flag = false;
			if (SP.empty()) break;
			list<SendPacket_t>::iterator sPacket;
			for (sPacket = SP.begin(); sPacket != SP.end();sPacket++){
				if (sPacket->TargetIP == ARPFrame.SrcIP){
					IPFrame = (IPFrame_t *)sPacket->PktData;
					cpyMAC(IPFrame->FrameHeader.DesMAC, ARPFrame.SrcHA);
					for (int t = 0; t < 6; t++){
						IPFrame->FrameHeader.SrcMAC[t] = IfInfo[sPacket->IfNo].MACAddr[t];
					}
					pcap_sendpacket(IfInfo[sPacket->IfNo].adhandle, (u_char *)sPacket->PktData, sPacket->len);
					SP.erase(sPacket);
					Logprint("Transmit IP Packet which desMAC is ARP Request MAC");
					Logprint("Send IP Packet: " + IPntoa(IPFrame->IPHeader.SrcIP) + " -> " + IPntoa(IPFrame->IPHeader.DesIP)
						+ "   " + MACntoa(IPFrame->FrameHeader.SrcMAC) + " -> " + MACntoa(IPFrame->FrameHeader.DesMAC));
					flag = true;
					break;
				}
			}
		} while (flag);
		ReleaseMutex(mMutex);
	}
}


bool IPQuery(ULONG IPaddr, UCHAR *p){
	list<IP_MAC_t>::iterator ip_mac;
	if (IP_MAC.empty()) return false;
	for (ip_mac = IP_MAC.begin(); ip_mac != IP_MAC.end();ip_mac++){
		if (IPaddr == ip_mac->IPAddr){
			for (int j = 0; j < 6; j++){
				p[j] = ip_mac->MACAddr[j];
			}
			return true;
		}
	}
	return false;
}

void IPPacketProc(IfInfo_t *pIfInfo, struct pcap_pkthdr *header, const u_char *pkt_data){
	IPFrame_t *IPFrame;
	SendPacket_t sPacket;
	IPFrame = (IPFrame_t *)pkt_data;
	Logprint("Receive IP Packet: " + IPntoa(IPFrame->IPHeader.SrcIP) + " -> " + IPntoa(IPFrame->IPHeader.DesIP));
	if (IPFrame->IPHeader.TTL <= 0){
		ICMPPacketProc(pIfInfo, 11, 0, pkt_data);
		return;
	}
	IPHeader_t *IpHeader = &(IPFrame->IPHeader);
	if (!IsChecksum((char *)IpHeader)){
		Logprint("IP Packet Checksum Error,discard data packet");
		return;
	}
	DWORD nextHop;
	UINT ifNo;
	if ((nextHop = RouteQuery(ifNo, IPFrame->IPHeader.DesIP, RouteTable)) == -1){
		ICMPPacketProc(pIfInfo, 3, 0, pkt_data);
		return;
	}
	else{
		sPacket.IfNo = ifNo;
		sPacket.TargetIP = nextHop;
		cpyMAC(IPFrame->FrameHeader.SrcMAC, IfInfo[sPacket.IfNo].MACAddr);
		IPFrame->IPHeader.TTL -= 1;
		unsigned short check_buff[sizeof(IPHeader_t)];
		IPFrame->IPHeader.Checksum = 0;
		memset(check_buff, 0, sizeof(IPHeader_t));
		IPHeader_t *ip_header = &(IPFrame->IPHeader);
		memcpy(check_buff, ip_header, sizeof(IPHeader_t));
		IPFrame->IPHeader.Checksum = ChecksumCompute(check_buff, sizeof(IPHeader_t));
		if (IPQuery(sPacket.TargetIP, IPFrame->FrameHeader.DesMAC)){
			memcpy(sPacket.PktData, pkt_data, header->len);
			sPacket.len = header->len;
			if (pcap_sendpacket(IfInfo[sPacket.IfNo].adhandle, (u_char *)sPacket.PktData, sPacket.len) != 0){
				Logprint("Send IP Packet Error :" + string(pcap_geterr(IfInfo[sPacket.IfNo].adhandle)));
				return;
			}

			Logprint("Transmit IP Packet: " + IPntoa(IPFrame->IPHeader.SrcIP) + " -> "
				+ IPntoa(IPFrame->IPHeader.DesIP) + "     " + MACntoa(IPFrame->FrameHeader.SrcMAC)
				+ " -> " + MACntoa(IPFrame->FrameHeader.DesMAC));
		}
		else{
			if (SP.size() < 65530){
				sPacket.len = header->len;
				memcpy(sPacket.PktData, pkt_data, header->len);
				WaitForSingleObject(mMutex, INFINITE);
				sPacket.n_mTimer = TimerCount;
				if (TimerCount++ > 65533) TimerCount = 1;
				SP.push_back(sPacket);
				ReleaseMutex(mMutex);
				Logprint("UnKnown Des MAC,put IP Packet in buffer: " + IPntoa(IPFrame->IPHeader.SrcIP) + " -> "
					+ IPntoa(IPFrame->IPHeader.DesIP) + "    " + MACntoa(IPFrame->FrameHeader.SrcMAC)
					+ "->XX:XX:XX:XX:XX:XX");
				Logprint("Send ARP Request");
				ARPRequest(IfInfo[sPacket.IfNo].adhandle, IfInfo[sPacket.IfNo].MACAddr, IfInfo[sPacket.IfNo].IP[1].IPAddr, sPacket.TargetIP);
			}
			else{
				Logprint("Buffer overflow,discard IP Packet: " + IPntoa(IPFrame->IPHeader.SrcIP) + " -> "
					+ IPntoa(IPFrame->IPHeader.DesIP) + "    " + MACntoa(IPFrame->FrameHeader.SrcMAC)
					+ "->XX:XX:XX:XX:XX:XX");
			}
		}
	}
}

DWORD RouteQuery(UINT &ifNo, DWORD desIP, list<RouteTable_t> routeTable){
	DWORD MaxMask = 0;
	int Index = -1;
	list<RouteTable_t>::iterator rt;
	DWORD tmp;
	for (rt = routeTable.begin(); rt != routeTable.end();rt++){
		if ((desIP&rt->Mask) == rt->DesIP){
			Index ++;
			if (rt->Mask >= MaxMask){
				ifNo = rt->IfNo;
				if (rt->NextHop == 0) tmp = desIP;
				else tmp = rt->NextHop;
			}
		}
	}
	if (Index == -1) return -1;
	else return tmp;
}

void ICMPPacketProc(IfInfo_t *pIfInfo, BYTE type, BYTE code, const u_char *pkt_data){
	u_char * ICMPBuf = new u_char[70];
	//fill Frame Header
	memcpy(((FrameHeader_t *)ICMPBuf)->DesMAC, ((FrameHeader_t*)pkt_data)->SrcMAC, 6);
	memcpy(((FrameHeader_t *)ICMPBuf)->SrcMAC, ((FrameHeader_t*)pkt_data)->DesMAC, 6);
	((FrameHeader_t *)ICMPBuf)->FrameType = htons(0x0800);

	//fill IP Header
	((IPHeader_t *)(ICMPBuf + 14))->Ver_HLen = ((IPHeader_t*)(pkt_data + 14))->Ver_HLen;
	((IPHeader_t *)(ICMPBuf + 14))->TOS = ((IPHeader_t*)(pkt_data + 14))->TOS;
	((IPHeader_t *)(ICMPBuf + 14))->TotalLen = htons(56);
	((IPHeader_t *)(ICMPBuf + 14))->ID = ((IPHeader_t*)(pkt_data + 14))->ID;
	((IPHeader_t *)(ICMPBuf + 14))->Flag_Seg = ((IPHeader_t*)(pkt_data + 14))->Flag_Seg;
	((IPHeader_t *)(ICMPBuf + 14))->TTL = 64;
	((IPHeader_t *)(ICMPBuf + 14))->UpProtocol = 1;
	((IPHeader_t *)(ICMPBuf + 14))->SrcIP = ((IPHeader_t*)(pkt_data + 14))->DesIP;
	((IPHeader_t *)(ICMPBuf + 14))->DesIP = ((IPHeader_t*)(pkt_data + 14))->SrcIP;
	((IPHeader_t *)(ICMPBuf + 14))->Checksum = htons(ChecksumCompute((unsigned short *)(ICMPBuf + 14), 20));
	
	//fill ICMP Header
	((ICMPHeader_t *)(ICMPBuf + 34))->Type = type;
	((ICMPHeader_t *)(ICMPBuf + 34))->Code = code;
	((ICMPHeader_t *)(ICMPBuf + 34))->ID = 0;
	((ICMPHeader_t *)(ICMPBuf + 34))->Sequence = 0;
	((ICMPHeader_t *)(ICMPBuf + 34))->Checksum = htons(ChecksumCompute((unsigned short *)(ICMPBuf + 34), 8));
	
	//fill data
	memcpy((u_char *)(ICMPBuf + 42), (IPHeader_t*)(pkt_data + 14), 20);
	memcpy((u_char*)(ICMPBuf + 62), (u_char *)(pkt_data + 34), 8);
	pcap_sendpacket(pIfInfo->adhandle, (u_char *)ICMPBuf, 70);
	if (type == 11)Logprint("Send ICMP Error: " + string(pcap_geterr(pIfInfo->adhandle)));
	if (type == 3)Logprint("Send ICMP timeout");
	Logprint("ICMP -> " + IPntoa(((IPHeader_t*)(ICMPBuf + 14))->DesIP) + " - " + MACntoa(((FrameHeader_t*)ICMPBuf)->DesMAC));
	delete[] ICMPBuf;
}


unsigned short ChecksumCompute(unsigned short *buffer, int size){
	unsigned long cksum = 0;
	while (size > 1){
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size){
		cksum += *(unsigned char *)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}


void CALLBACK OnTimer(HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime){

	list<SendPacket_t>::iterator sPacket;
	IPFrame_t *IPFrame;
	if (SP.empty()){
		return;
	}
	WaitForSingleObject(mMutex, INFINITE);
	for (sPacket = SP.begin(); sPacket != SP.end();){
		if (sPacket->n_mTimer == iTimerID){
			IPFrame = (IPFrame_t*)sPacket->PktData;
			Logprint("Timer delete IP Packet: " + IPntoa(IPFrame->IPHeader.SrcIP) + " -> "
				+ IPntoa(IPFrame->IPHeader.DesIP) + "     " +
				MACntoa(IPFrame->FrameHeader.SrcMAC) + "-> XX:XX:XX:XX:XX:XX");
			KillTimer(hwnd, iTimerID);
			sPacket = SP.erase(sPacket);
		}
		else{
			sPacket++;
		}
	}
	ReleaseMutex(mMutex);
}