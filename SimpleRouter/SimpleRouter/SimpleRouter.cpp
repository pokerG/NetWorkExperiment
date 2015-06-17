// SimpleRouter.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "SimpleRouter.h"
#include "protocol.h"
#include "pcap.h"
#include <ctime>
#include <cstdio>
#include <iostream>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// The one and only application object

CWinApp theApp;

using namespace std;

//Global Variable 
IfInfo_t IfInfo[MAX_INTERFACE];
int IfCount;  //the size of interface
UINT_PTR TimerCount;
CList<SendPacket_t, SendPacket_t&> SP; //the buffer queue of SendPacket
CList <IP_MAC_t, IP_MAC_t&> IP_MAC; //the list of IP_MAC mapping
CList <RouteTable_t, RouteTable_t&> RouteTable;
CMutex mMutex(0, 0, 0);

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
	ip_header->Checksum = ChecksumCompute(check_buff,sizeof(IPHeader_t));
	if(ip_header->Checksum == checksumBuf){
		return true;
	}else{
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




UINT CaptureLocalARP(PVOID pParam)
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
	POSITION pos, CurrentPos;
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
			IP_MAC.AddHead(ip_mac);
			Logprint("this correspondence insert to IP-MAC Mapping");
		}
		mMutex.Lock(INFINITE);
		do{
			flag = false;
			if (SP.IsEmpty()) break;
			pos = SP.GetHeadPosition();
			for (int i = 0; i < SP.GetCount(); i++){
				CurrentPos = pos;
				sPacket = SP.GetNext(pos);
				if (sPacket.TargetIP == ARPFrame.SrcIP){
					IPFrame = (IPFrame_t *)sPacket.PktData;
					cpyMAC(IPFrame->FrameHeader.DesMAC, ARPFrame.SrcHA);
					for (int t = 0; t < 6; t++){
						IPFrame->FrameHeader.SrcMAC[t] = IfInfo[sPacket.IfNo].MACAddr[t];
					}
					pcap_sendpacket(IfInfo[sPacket.IfNo].adhandle, (u_char *)sPacket.PktData, sPacket.len);
					SP.RemoveAt(CurrentPos);
					Logprint("Transmit IP Packet which desMAC is ARP Request MAC");
					Logprint("Send IP Packet: " + IPntoa(IPFrame->IPHeader.SrcIP) + " -> " + IPntoa(IPFrame->IPHeader.DesIP)
						+ "   " + MACntoa(IPFrame->FrameHeader.SrcMAC) + " -> " + MACntoa(IPFrame->FrameHeader.DesMAC));
					flag = true;
					break;
				}
			}
		} while (flag);
		mMutex.Unlock();
	}
}


bool IPQuery(ULONG IPaddr, UCHAR *p){
	IP_MAC_t ip_mac;
	POSITION pos;
	if (IP_MAC.IsEmpty()) return false;
	pos = IP_MAC.GetHeadPosition();
	for (int i = 0; i < IP_MAC.GetCount(); i++){
		ip_mac = IP_MAC.GetNext(pos);
		if (IPaddr == ip_mac.IPAddr){
			for (int j = 0; j < 6; j++){
				p[j] = ip_mac.MACAddr[j];
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
	if ((nextHop = RouteQuery(ifNo, IPFrame->IPHeader.DesIP, &RouteTable)) == -1){
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
			if (SP.GetCount() < 65530){
				sPacket.len = header->len;
				memcpy(sPacket.PktData, pkt_data, header->len);
				mMutex.Lock(INFINITE);
				sPacket.n_mTimer = TimerCount;
				if (TimerCount++ > 65533) TimerCount = 1;
				SP.AddTail(sPacket);
				mMutex.Unlock();
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

DWORD RouteQuery(UINT &ifNO, DWORD desIP, CList <RouteTable_t, RouteTable_t&> *routeTable){
	DWORD MaxMask = 0;
	int Index = -1;
	POSITION pos;
	RouteTable_t rt;
	DWORD tmp;
	pos = routeTable->GetHeadPosition();
	for (int i = 0; i < routeTable->GetCount(); i++){
		rt = routeTable->GetNext(pos);
		if ((desIP&rt.Mask) == rt.DesIP){
			Index = i;
			if (rt.Mask >= MaxMask){
				ifNO = rt.IfNo;
				if (rt.NextHop == 0) tmp = desIP;
				else tmp = rt.NextHop;
			}
		}
	}
	if (Index == -1) return -1;
	else return tmp;
}

void ICMPPacketProc(IfInfo_t *pIfInfo, BYTE type, BYTE code, const u_char *pkt_data){
	u_char * ICMPBuf = new u_char[70];
	memcpy(((FrameHeader_t *)ICMPBuf)->DesMAC, ((FrameHeader_t*)pkt_data)->SrcMAC, 6);
	memcpy(((FrameHeader_t *)ICMPBuf)->SrcMAC, ((FrameHeader_t*)pkt_data)->DesMAC, 6);
	((FrameHeader_t *)ICMPBuf)->FrameType = htons(0x0800);
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
	((ICMPHeader_t *)(ICMPBuf + 34))->Type = type;
	((ICMPHeader_t *)(ICMPBuf + 34))->Code = code;
	((ICMPHeader_t *)(ICMPBuf + 34))->ID = 0;
	((ICMPHeader_t *)(ICMPBuf + 34))->Sequence = 0;
	((ICMPHeader_t *)(ICMPBuf + 34))->Checksum = htons(ChecksumCompute((unsigned short *)(ICMPBuf + 34), 8));
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

	SendPacket_t sPacket;
	IPFrame_t *IPFrame;
	POSITION pos, CurrentPos;

	if (SP.IsEmpty()){
		return;
	}

	mMutex.Lock(INFINITE);
	//WaitForSingleObject(mMutex, INFINITE);
	pos = SP.GetHeadPosition();
	for (int i = 0; i < SP.GetCount(); i++){
		CurrentPos = pos;
		sPacket = SP.GetNext(pos);
		if (sPacket.n_mTimer == iTimerID){
			IPFrame = (IPFrame_t*)sPacket.PktData;
			Logprint("Timer delete IP Packet: " + IPntoa(IPFrame->IPHeader.SrcIP) + " -> "
				+ IPntoa(IPFrame->IPHeader.DesIP) + "     " +
				MACntoa(IPFrame->FrameHeader.SrcMAC) + "-> XX:XX:XX:XX:XX:XX");
			KillTimer(hwnd, iTimerID);
			SP.RemoveAt(CurrentPos);
		}
	}
	mMutex.Unlock();
	//ReleaseMutex(mMutex);
}

void work(){
	pcap_if_t *alldevs, *d;
	pcap_addr_t *a;
	struct bpf_program fcode;
	char errbuf[PCAP_ERRBUF_SIZE], strbuf[1000];
	int i, j, k;
	IP_t ipaddr;
	UCHAR srcMAC[6];
	ULONG srcIP;
	//SetTimer(3999, 10000, 0);
	//Get local device list
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		Logprint("pcap_findalldevs_ex error: " + string(errbuf));
		exit(0);
	}
	i = j = k = 0;
	//Get IP Address Info
	for (d = alldevs; d != NULL; d = d->next){
		if (d->addresses != NULL){
			IfInfo[i].DeviceName = d->name;
			IfInfo[i].Description = d->description;
			for (a = d->addresses; a; a = a->next){
				if (a->addr->sa_family = AF_INET){
					ipaddr.IPAddr = (((sockaddr_in *)a->addr)->sin_addr.s_addr);
					ipaddr.IPMask = (((sockaddr_in *)a->netmask)->sin_addr.s_addr);
					IfInfo[i].IP.Add(ipaddr);
					j++;
				}
			}
			if (i == MAX_INTERFACE) //handle interface celling
				break;
			else 
				i++;

		}
	}
	if (j < 2){
		Logprint("Must have no fewer than two IP address");
		exit(0);
	}
	IfCount = i;
	for (i = 0; i < IfCount; i++){
		if ((IfInfo[i].adhandle = pcap_open(IfInfo[i].DeviceName.c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL){
			Logprint("Interface can't open.WinCap not support " + IfInfo[i].DeviceName);
			exit(0);
		}
	}

	//Create thread capture,get local interface MAC
	CWinThread* pthread;
	for (i = 0; i < IfCount; i++){
		pthread = AfxBeginThread(CaptureLocalARP, &IfInfo[i], THREAD_PRIORITY_NORMAL);
		if (!pthread){
			Logprint("Create CaptureLocalARP Thread failed");
			exit(0);
		}
	}
	//clear list's MAC
	for (i = 0; i < IfCount; i++) 
		setMAC(IfInfo[i].MACAddr, 0);

	setMAC(srcMAC, 66);
	srcIP = inet_addr("112.112.112.112");
	for (i = 0; i < IfCount; i++) {
		ARPRequest(IfInfo[i].adhandle, srcMAC, srcIP, IfInfo[i].IP[1].IPAddr);
	}
	//ensure all interface's MAC can receive
	setMAC(srcMAC, 0);
	do{
		Sleep(1000);
		k = 0;
		for (i = 0; i < IfCount; i++){
			if (!cmpMAC(IfInfo[i].MACAddr, srcMAC)){
				k++;
				continue;
			}
			else {
				break;
			}
		}
	} while (!((j++ > 10) || (k == IfCount)));
	if (k != IfCount){
		Logprint("At least one interface's MAC not received");
		exit(0);
	}

	//print interface info
	for (i = 0; i < IfCount; i++){
		cout << "Interface: \n";
		cout << "     Device: " << IfInfo[i].DeviceName << endl;
		cout << "     Description: " << IfInfo[i].Description << endl;
		cout << "     MAC Address: " << MACntoa(IfInfo[i].MACAddr) << endl;
		for (j = 0; j < IfInfo[i].IP.GetSize(); j++){
			cout << "     IP Address: " << IPntoa(IfInfo[i].IP[j].IPAddr) << endl;
		}
	}

	//init RouteTable
	RouteTable_t rt;
	for (i = 0; i < IfCount; i++){
		for (j = 0; j < IfInfo[i].IP.GetSize(); j++){
			rt.IfNo = i;
			rt.DesIP = IfInfo[i].IP[j].IPAddr & IfInfo[i].IP[j].IPMask;
			rt.Mask = IfInfo[i].IP[j].IPMask;
			rt.NextHop = 0;
			RouteTable.AddTail(rt);
		}
	}

	//set filter rule,receive arp and frame which need route
	string Filter, Filter0, Filter1;
	Filter0 = "(";
	Filter1 = "(";
	for (i = 0; i < IfCount; i++){
		Filter0 += "(ether dst " + MACntoa(IfInfo[i].MACAddr) + ")";
		for (j = 0; j < IfInfo[i].IP.GetSize(); j++){
			Filter1 += "(ip dst host " + IPntoa(IfInfo[i].IP[j].IPAddr) + ")";
			if (((j == (IfInfo[i].IP.GetSize() - 1))) && (i == (IfCount - 1)))	Filter1 += ")";
			else Filter1 += " or ";
		}
		if (i == (IfCount - 1)) Filter0 += ")";
		else Filter0 += " or ";
	}
	Filter = Filter0 + " and ((arp and (ether[21]=0x2)) or (not" + Filter1 + "))";
	sprintf_s(strbuf, "%s", Filter.c_str());
	
	for (i = 0; i < IfCount; i++){
		if (pcap_compile(IfInfo[i].adhandle, &fcode, strbuf, 1, IfInfo[i].IP[1].IPMask) < 0){
			Logprint("Filter rule Compile Failed");
			exit(0);
		}
		if (pcap_setfilter(IfInfo[i].adhandle, &fcode) < 0){
			Logprint("Set Filter Error");
			exit(0);
		}
	}
	pcap_freealldevs(alldevs);
	TimerCount = 1;
	for (i = 0; i < IfCount; i++){
		pthread = AfxBeginThread(Capture, &IfInfo[i], THREAD_PRIORITY_NORMAL);
		if (!pthread){
			Logprint("Create CaptureLocalARP Thread failed");
			exit(0);
		}
	}
}

void init(){
	pcap_if_t *alldevs, *d;
	pcap_addr_t *a;
	struct bpf_program fcode;
	char errbuf[PCAP_BUF_SIZE], strbuf[1000];
	IP_t *ipaddr = NULL;
	UCHAR srcMAC[6];
	ULONG srcIP;
	int i = 0, j = 0, k = 0;
	//TODO SetTimer
	SetTimer(NULL, 3999, 10000, OnTimer);
	//Get local device list
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
		Logprint("pcap_findalldevs_ex error: " + string(errbuf));
		exit(0);
	}
	//Get IP Address Info
	for (d = alldevs; d != NULL; d = d->next){
		if (d->addresses != NULL){ //Discard moden
			IfInfo[i].DeviceName = d->name;
			IfInfo[i].Description = d->description;
			for (a = d->addresses; a; a = a->next){
				if (a->addr->sa_family == AF_INET){
					ipaddr = new IP_t();
					ipaddr->IPAddr = (((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
					ipaddr->IPMask = (((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
					IfInfo[i].IP.Add(*ipaddr);
					j++;
				}
			}
			i++;
			if (i == MAX_INTERFACE){	//handle interface celling
				break;
			}
		}
	}

	if (j < 2){
		Logprint("Must have no fewer than two IP address");
		exit(0);
	}
	IfCount = i;

	for (i = 0; i < IfCount; i++){
		if ((IfInfo[i].adhandle = pcap_open(IfInfo[i].DeviceName.data(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL){
			Logprint("Interface can't open.WinCap not support " + IfInfo[i].DeviceName);
			exit(0);
		}
	}
	
	//Create thread capture,get local interface MAC
	CWinThread *pthread;
	for (i = 0; i < IfCount; i++){
		pthread = AfxBeginThread(CaptureLocalARP, &IfInfo[i], THREAD_PRIORITY_NORMAL);
		if (!pthread){
			Logprint("Create CaptureLocalARP Thread failed");
			exit(0);
		}
	}

	//clear list's MAC
	for (i = 0; i < IfCount; i++){
		setMAC(IfInfo[i].MACAddr, 0);
	}

	//in order to get real MAC, use virtual MAC and IP send ARP Request to local
	setMAC(srcMAC, 66); //set virtual MAC
	srcIP = inet_addr("112.112.112.112");
	for (i = 0; i < IfCount; i++){
		ARPRequest(IfInfo[i].adhandle, srcMAC, srcIP, IfInfo[i].IP[0].IPAddr);
	}

	//ensure all interface's MAC can receive
	setMAC(srcMAC, 0);
	do{
		Sleep(1000);
		k = 0;
		for (i = 0; i < IfCount; i++){
			if (!cmpMAC(IfInfo[i].MACAddr, srcMAC)){
				k++;
			}
			else{
				break;
			}
		}
	} while (!((j++ > 10) || (k == IfCount)));

	if (k != IfCount){
		Logprint("At least one interface's MAC not received");
		exit(0);
	}

	//print interface info
	for (i = 0; i < IfCount; i++){
		cout<<"Interface: \n";
		cout<<"     Device: "<<IfInfo[i].DeviceName<<endl;
		cout<<"     Description: "<<IfInfo[i].Description<<endl;
		cout<<"     MAC Address: "<<MACntoa(IfInfo[i].MACAddr)<<endl;
		for (j = 0; j < IfInfo[i].IP.GetSize(); j++){
			cout<<"     IP Address: "<<IPntoa(IfInfo[i].IP[j].IPAddr)<<endl;
		}
	}

	//init RouteTable
	RouteTable_t rt;
	for (i = 0; i < IfCount; i++){
		for (j = 0; j < IfInfo[i].IP.GetSize(); j++){
			rt.IfNo = i;
			rt.DesIP = IfInfo[i].IP[j].IPAddr & IfInfo[i].IP[j].IPMask;
			rt.Mask = IfInfo[i].IP[j].IPMask;
			rt.NextHop = 0;
			RouteTable.AddTail(rt);
		}
	}

	//set filter rule,receive arp and frame which need route
	string Filter, Filter0, Filter1;
	Filter0 = "(";
	Filter1 = "(";
	for (i = 0; i < IfCount; i++)
	{
		Filter0 += "(ether dst " + MACntoa(IfInfo[i].MACAddr) + ")";
		for (j = 0; j < IfInfo[i].IP.GetSize(); j++){
			Filter1 += "(IP dst host " + IPntoa(IfInfo[i].IP[j].IPAddr) + ")";
			if (((j == (IfInfo[i].IP.GetSize() - 1))) && (i == (IfCount - 1))){
				Filter1 += ")";
			}
			else{
				Filter1 += " or ";
			}
		}
		if (i == (IfCount - 1)){
			Filter0 += ")";
		}
		else{
			Filter0 += " or ";
		}
	}
	Filter = Filter0 + " and ((arp and (ether[21]=0x2)) or (not" + Filter1 + "))";
	sprintf(strbuf, "%s", Filter.c_str());
	for (i = 0; i < IfCount; i++){
		if (pcap_compile(IfInfo[i].adhandle, &fcode, strbuf, 1, IfInfo[i].IP[0].IPMask) < 0){
			Logprint("Filter rule Compile Failed");
			exit(0);
		}
		if (pcap_setfilter(IfInfo[i].adhandle, &fcode) < 0){
			Logprint("Set Filter Error");
			exit(0);
		}
	}
	pcap_freealldevs(alldevs);
	TimerCount = 1;
	for (i = 0; i < IfCount; i++){
		pthread = AfxBeginThread(Capture, &IfInfo[i], THREAD_PRIORITY_NORMAL);
		if (!pthread){
			Logprint("Create CaptureLocalARP Thread failed");
			exit(0);
		}
	}

}

void AddRouter(string mask, string desIP, string nexthop){
	int i, j;
	DWORD ipaddr;
	RouteTable_t rt;
	ipaddr = inet_addr(nexthop.data());

	for (i = 0; i < IfCount; i++){
		for (j = 0; j < IfInfo[i].IP.GetSize(); j++){
			if (((IfInfo[i].IP[j].IPAddr)&(IfInfo[i].IP[j].IPMask)) == ((IfInfo[i].IP[j].IPMask)&ipaddr)){
				rt.IfNo = i;
				rt.Mask = inet_addr(mask.data());
				rt.DesIP = inet_addr(desIP.data());
				rt.NextHop = inet_addr(nexthop.data());
				RouteTable.AddTail(rt);
			}
		}
	}
}

void DeleteRouter(string mask, string desIP, string nexthop){
	int i;
	RouteTable_t rt;
	POSITION pos, CurrentPos;
	if (RouteTable.IsEmpty()){
		return;
	}

	pos = RouteTable.GetHeadPosition();
	for (i = 0; i < RouteTable.GetCount();i++){
		CurrentPos = pos;
		rt = RouteTable.GetNext(pos);
		if (rt.Mask == inet_addr(mask.data()) 
			&& rt.DesIP == inet_addr(desIP.data()) 
			&& rt.NextHop == inet_addr(nexthop.data())){
			RouteTable.RemoveAt(CurrentPos);
			return;
		}
	}

}

void listRouteTable(){
	int i;
	RouteTable_t rt;
	POSITION pos, CurrentPos;
	if (RouteTable.IsEmpty()){
		return;
	}
	pos = RouteTable.GetHeadPosition();
	for (i = 0; i < RouteTable.GetCount(); i++){
		CurrentPos = pos;
		rt = RouteTable.GetNext(pos);
		if (rt.NextHop == 0){
			cout << IPntoa(rt.DesIP) << "\t" << IPntoa(rt.Mask) << "\t" << "direct" << "\t" << rt.IfNo << endl;
		}
		else{
			cout << IPntoa(rt.DesIP) << "\t" << IPntoa(rt.Mask) << "\t" << IPntoa(rt.NextHop) << "\t" << rt.IfNo << endl;
		}
		
	}
}

void GetCmd(){
	string cmd, mask, des, nexthop;
	while (cin >> cmd){
		if (cmd == "list"){
			listRouteTable();
		}
		else if (cmd == "add"){
			cin >> des >> mask >> nexthop;
			AddRouter(mask, des, nexthop);
		}
		else if (cmd == "delete"){
			cin >> des >> mask >> nexthop;
			DeleteRouter(mask, des, nexthop);
		}
	}

}

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	int nRetCode = 0;

	HMODULE hModule = ::GetModuleHandle(NULL);

	if (hModule != NULL)
	{
		// initialize MFC and print and error on failure
		if (!AfxWinInit(hModule, NULL, ::GetCommandLine(), 0))
		{
			// TODO: change error code to suit your needs
			_tprintf(_T("Fatal Error: MFC initialization failed\n"));
			nRetCode = 1;
		}
		else
		{
			// TODO: code your application's behavior here.x`
			Logprint("Start");
			work();
			GetCmd();
		}
	}
	else
	{
		// TODO: change error code to suit your needs
		_tprintf(_T("Fatal Error: GetModuleHandle failed\n"));
		nRetCode = 1;
	}

	return nRetCode;
}
