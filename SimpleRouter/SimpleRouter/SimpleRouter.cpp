// SimpleRouter.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "SimpleRouter.h"
#include "protocol.h"
#include "pcap.h"
#include <ctime>
#include <cstdio>
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
	printf("%d-%02d-%02d %02d:%02d:%02d     %s\n",
		t->tm_year + 1900,
		t->tm_mon + 1,
		t->tm_mday,
		t->tm_hour,
		t->tm_min,
		t->tm_sec,
		str.data());
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
		if (MAC1[i] != MAC2[i]){
			return false;
		}
	}
	return true;
}

string IPntoa(ULONG nIPAddr){
	char strbuf[50];
	u_char *p;
	string str;
	p = (u_char*)&nIPAddr;
	sprintf(strbuf, "%03d.%03d.%03d.%03d", p[0], p[1], p[2], p[3]);
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

	USHORT check_buff[sizeof(IPHeader_t)];
	memcpy(check_buff, ip_header, sizeof(IPHeader_t));

	if (ChecksumCompute(check_buff, sizeof(IPHeader_t)) != 0){
		return false;
	}
	else{
		return true;
	}
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
			fh = (FrameHeader_t *)(pkt_data);
			switch (ntohs(fh->FrameType))
			{
			case 0x0806: //ARP
				ARPPacketProc(header, pkt_data);
				break;
			case 0x0800: //IP
				IPPacketProc(pIfInfo, header, pkt_data);
			default:
				break;
			}
		}
		else if (res == -1){
			fprintf(stderr, "Error reading data packet: %s\n", pcap_geterr(pIfInfo->adhandle));
			return -1;
		}
	}
	return 0;
}


UINT CaptureLocalARP(PVOID pParam){
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	IfInfo_t *pIfInfo;
	ARPFrame_t *ARPFrame;
	string DisplayStr;
	pIfInfo = (IfInfo_t *)pParam;
	while (true){
		Sleep(50);
		res = pcap_next_ex(pIfInfo->adhandle, &header, &pkt_data);
		if (res == 0){
			continue;
		} else if (res > 0){
			ARPFrame = (ARPFrame_t *)(pkt_data);
			if ((ARPFrame->FrameHeader.FrameType == htons(0x0806))
				&& (ARPFrame->Operation == htons(0x0002))
				&& (ARPFrame->SrcIP == pIfInfo->IP[0].IPAddr)){
				cpyMAC(pIfInfo->MACAddr, ARPFrame->SrcHA);
				return 0;
			}
		}
		else if (res == -1){
			fprintf(stderr, "Error reading Local ARP: %s\n", pcap_geterr(pIfInfo->adhandle));
			return -1;
		}
	}
}

void ARPPacketProc(struct pcap_pkthdr *headr, const u_char * pkt_data){
	bool flag;
	ARPFrame_t ARPFrame;
	IPFrame_t *IPFrame;
	SendPacket_t sPacket;
	POSITION pos, CurrentPos;
	IP_MAC_t ip_mac;
	UCHAR MACAddr[6];

	ARPFrame = *(ARPFrame_t *)pkt_data;
	if (ARPFrame.Operation == ntohs(0x0002)){
		Logprint("Receive ARP Response");
		Logprint("ARP " + (IPntoa(ARPFrame.SrcIP)) + " -- " + MACntoa(ARPFrame.SrcHA));
		if (IPQuery(ARPFrame.SrcIP, MACAddr)){ //handle IP-MAC Mapping
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
		//WaitForSingleObject(mMutex, INFINITE);
		do{	//transmit IP packet in buffer
			flag = false;
			if (SP.IsEmpty()){
				break;
			}
			//ergodic buffer
			pos = SP.GetHeadPosition();
			for (int i = 0; i < SP.GetCount(); i++){
				CurrentPos = pos;
				sPacket = SP.GetNext(pos);
				if (sPacket.TargetIP == ARPFrame.SrcIP){
					IPFrame = (IPFrame_t *)sPacket.PktData;
					cpyMAC(IPFrame->FrameHeader.DesMAC, ARPFrame.SrcHA);
					cpyMAC(IPFrame->FrameHeader.SrcMAC, IfInfo[sPacket.IfNo].MACAddr);
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
		//ReleaseMutex(mMutex);
	}
}

bool IPQuery(ULONG IPaddr, UCHAR *p){
	if (IP_MAC.IsEmpty())
		return false;
	POSITION pos;
	IP_MAC_t ip_mac;
	pos = IP_MAC.GetHeadPosition();
	for (int i = 0; i < IP_MAC.GetCount(); i++){
		ip_mac = IP_MAC.GetNext(pos);
		if (IPaddr == ip_mac.IPAddr){
			cpyMAC(p, ip_mac.MACAddr);
		}
		return true;
	}
	return false;
}

void IPPacketProc(IfInfo_t *PIfInfo, struct pcap_pkthdr *header, const u_char *pkt_data){
	IPFrame_t *IPFrame;
	SendPacket_t sPacket;

	IPFrame = (IPFrame_t *)pkt_data;

	Logprint("Receive IP Packet: " + IPntoa(IPFrame->IPHeader.SrcIP) + " -> " + IPntoa(IPFrame->IPHeader.DesIP));

	if (IPFrame->IPHeader.TTL <= 0){ //ICMP timeout
		ICMPPacketProc(PIfInfo, 11, 0, pkt_data);
		return;
	}

	IPHeader_t *IPHeader = &(IPFrame->IPHeader);
	if (!IsChecksum((char *)IPHeader)){ //ICMP Error
		Logprint("IP Packet Checksum Error,discard data packet");
		return;
	}
	DWORD nextHop;
	UINT IfNo;
	if ((nextHop = RouteQuery(IfNo, IPFrame->IPHeader.DesIP, &RouteTable)) == -1){ //ICMP Des not reachable
		ICMPPacketProc(PIfInfo, 3, 0, pkt_data);
		return;
	}
	else{
		sPacket.IfNo = IfNo;
		sPacket.TargetIP = nextHop; //Why?
		cpyMAC(IPFrame->FrameHeader.SrcMAC, IfInfo[sPacket.IfNo].MACAddr);
		IPFrame->IPHeader.TTL -= 1;
		USHORT check_buff[sizeof(IPHeader_t)];
		IPFrame->IPHeader.Checksum = 0;
		IPHeader_t * ip_header = &(IPFrame->IPHeader);
		memcpy(check_buff, ip_header, sizeof(IPHeader_t));
		IPFrame->IPHeader.Checksum = ChecksumCompute(check_buff, sizeof(IPHeader_t));

		if (IPQuery(sPacket.TargetIP, IPFrame->FrameHeader.DesMAC)){
			memcpy(sPacket.PktData, pkt_data, header->len);
			sPacket.len = header->len;
			if (pcap_sendpacket(IfInfo[sPacket.IfNo].adhandle, (u_char*)sPacket.PktData, sPacket.len) != 0){
				Logprint("Send IP Packet Error :" + string(pcap_geterr(IfInfo[sPacket.IfNo].adhandle)));
				return;
			}
			Logprint("Transmit IP Packet: " + IPntoa(IPFrame->IPHeader.SrcIP) + " -> "
				+ IPntoa(IPFrame->IPHeader.DesIP) + "     " + MACntoa(IPFrame->FrameHeader.SrcMAC)
				+ " -> " + MACntoa(IPFrame->FrameHeader.DesMAC));
		}
		else{	//insert to buffer queue
			if (SP.GetCount() < 65530){
				sPacket.len = header->len;
				memcpy(sPacket.PktData, pkt_data, header->len);
				mMutex.Lock(INFINITE);
				//WaitForSingleObject(mMutex, INFINITE);
				sPacket.n_mTimer = TimerCount;
				if (TimerCount++ > 65533){
					TimerCount = 1;
				}
				//TODO: SetTimer
				SetTimer(NULL, sPacket.n_mTimer, 10000, OnTimer);
				SP.AddTail(sPacket);
				mMutex.Unlock();
				//ReleaseMutex(mMutex);
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


DWORD RouteQuery(UINT &IfNo, DWORD desIP, CList <RouteTable_t, RouteTable_t&> *routeTable){
	DWORD MaxMAsk = 0; //Get the longest mask;
	int index = -1;
	DWORD tmp;
	POSITION pos;
	RouteTable_t rt;

	pos = routeTable->GetHeadPosition();
	for (int i = 0; i < routeTable->GetCount(); i++){
		rt = routeTable->GetNext(pos);
		if ((desIP &rt.Mask) == rt.DesIP){
			index = i;
			if (rt.Mask >= MaxMAsk){
				IfNo = rt.IfNo;
				if (rt.NextHop == 0){ //direct
					tmp = desIP;
				}
				else{
					tmp = rt.NextHop;
				}
			}
		}
	}
	if (index == -1){
		return -1;
	}
	else{
		return tmp;
	}
}

void ICMPPacketProc(IfInfo_t *pIfInfo, BYTE type, BYTE code, const u_char *pkt_data){
	u_char *ICMPBuf = new u_char[70];
	//fill Frame Header
	memcpy(((FrameHeader_t*)ICMPBuf)->DesMAC, ((FrameHeader_t*)pkt_data)->SrcMAC, 6);
	memcpy(((FrameHeader_t*)ICMPBuf)->SrcMAC, ((FrameHeader_t*)pkt_data)->DesMAC, 6);
	((FrameHeader_t*)ICMPBuf)->FrameType = htons(0x0800);

	//fill IP Header
	((IPHeader_t*)(ICMPBuf + 14))->Ver_HLen = ((IPHeader_t*)(pkt_data + 14))->Ver_HLen;
	((IPHeader_t*)(ICMPBuf + 14))->TOS = ((IPHeader_t*)(pkt_data + 14))->TOS;
	((IPHeader_t*)(ICMPBuf + 14))->TotalLen = htons(56);
	((IPHeader_t*)(ICMPBuf + 14))->ID = ((IPHeader_t*)(pkt_data + 14))->ID;
	((IPHeader_t*)(ICMPBuf + 14))->Flag_Seg = ((IPHeader_t*)(pkt_data + 14))->Flag_Seg;
	((IPHeader_t*)(ICMPBuf + 14))->TTL = 64;
	((IPHeader_t*)(ICMPBuf + 14))->UpProtocol = 1;
	((IPHeader_t*)(ICMPBuf + 14))->SrcIP = ((IPHeader_t*)(pkt_data + 14))->DesIP;
	((IPHeader_t*)(ICMPBuf + 14))->DesIP = ((IPHeader_t*)(pkt_data + 14))->SrcIP;
	((IPHeader_t*)(ICMPBuf + 14))->Checksum = htons(ChecksumCompute((USHORT*)(ICMPBuf + 14), 20));

	//fill ICMP Header
	((ICMPHeader_t*)(ICMPBuf + 34))->Type = type;
	((ICMPHeader_t*)(ICMPBuf + 34))->Code = code;
	((ICMPHeader_t*)(ICMPBuf + 34))->ID = 0;
	((ICMPHeader_t*)(ICMPBuf + 34))->Sequence = 0;
	((ICMPHeader_t*)(ICMPBuf + 34))->Checksum = htons(ChecksumCompute((USHORT*)(ICMPBuf + 34), 8));

	//fill data
	memcpy((u_char*)(ICMPBuf + 42), (IPHeader_t*)(pkt_data + 14), 20);
	memcpy((u_char*)(ICMPBuf + 62), (u_char*)(pkt_data + 34), 8);

	if (pcap_sendpacket(pIfInfo->adhandle, (u_char*)ICMPBuf, 70) != 0){
		Logprint("Send ICMP Error: " + string(pcap_geterr(pIfInfo->adhandle)));
		return;
	}
	if (type == 11){
		Logprint("Send ICMP timeout");
	}
	else if (type == 3){
		Logprint("Send ICMP Des not reachable");
	}
	Logprint("ICMP -> " + IPntoa(((IPHeader_t*)(ICMPBuf + 14))->DesIP) + " - " + MACntoa(((FrameHeader_t*)ICMPBuf)->DesMAC));
	delete[]ICMPBuf;
}

USHORT ChecksumCompute(USHORT *buffer, int size){
	ULONG cksum = 0;
	while (size > 1){
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size){
		//maybe have 8bits alone
		cksum += *(UCHAR*)buffer;
	}

	//add hight 16bits to low 16bits
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
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

void init(){
	pcap_if_t *alldevs, *d;
	pcap_addr_t *a;
	struct bpf_program fcode;
	char errbuf[PCAP_BUF_SIZE], strbuf[1000];
	IP_t ipaddr;
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
					ipaddr.IPAddr = (((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
					ipaddr.IPMask = (((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
					IfInfo[i].IP.Add(ipaddr);
					j++;
				}
			}
			if (i == MAX_INTERFACE){	//handle interface celling
				break;
			}
			else{
				i++;
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
	Logprint("!!!!!");
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
		printf("Interface: ");
		printf("     Device: %s\n", IfInfo[i].DeviceName);
		printf("     Description: %s\n", IfInfo[i].Description);
		printf("     MAC Address: %s\n", MACntoa(IfInfo[i].MACAddr));
		for (j = 0; j < IfInfo[i].IP.GetSize(); j++){
			printf("     IP Address: %s\n", IPntoa(IfInfo[i].IP[j].IPAddr));
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
	sprintf(strbuf, "%s", Filter);
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
	ipaddr = htonl(inet_addr(nexthop.data()));

	for (i = 0; i < IfCount; i++){
		for (j = 0; j < IfInfo[i].IP.GetSize(); j++){
			if (((IfInfo[i].IP[j].IPAddr)&(IfInfo[i].IP[j].IPMask)) == ((IfInfo[i].IP[j].IPMask)&ipaddr)){
				rt.IfNo = i;
				rt.Mask = htonl(inet_addr(mask.data()));
				rt.DesIP = htonl(inet_addr(desIP.data()));
				rt.NextHop = htonl(inet_addr(nexthop.data()));
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
		if (rt.Mask == htonl(inet_addr(mask.data())) 
			&& rt.DesIP == htonl(inet_addr(desIP.data())) 
			&& rt.NextHop == htonl(inet_addr(nexthop.data()))){
			RouteTable.RemoveAt(CurrentPos);
			return;
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
			// TODO: code your application's behavior here.
			init();
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
