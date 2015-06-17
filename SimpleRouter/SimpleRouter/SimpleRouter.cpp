// SimpleRouter.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "protocol.h"
#include "router.h"
#include "pcap.h"
#include <iostream>
using namespace std;

//Global Variable 
IfInfo_t IfInfo[MAX_INTERFACE];
int IfCount;  //the size of interface
UINT_PTR TimerCount;
list<SendPacket_t> SP; //the buffer queue of SendPacket
list<IP_MAC_t> IP_MAC; //the list of IP_MAC mapping
list<RouteTable_t> RouteTable;
//CMutex mMutex(0, 0, 0);
HANDLE mMutex;

void init(){
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
					IfInfo[i].IP.push_back(ipaddr);
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
	HANDLE pthread;
	for (i = 0; i < IfCount; i++){
		pthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CaptureLocalARP, &IfInfo[i], 0, NULL);
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
		for (j = 0; j < IfInfo[i].IP.size(); j++){
			cout << "     IP Address: " << IPntoa(IfInfo[i].IP[j].IPAddr) << endl;
		}
	}

	//init RouteTable
	RouteTable_t rt;
	for (i = 0; i < IfCount; i++){
		for (j = 0; j < IfInfo[i].IP.size(); j++){
			rt.IfNo = i;
			rt.DesIP = IfInfo[i].IP[j].IPAddr & IfInfo[i].IP[j].IPMask;
			rt.Mask = IfInfo[i].IP[j].IPMask;
			rt.NextHop = 0;
			RouteTable.push_back(rt);
		}
	}

	//set filter rule,receive arp and frame which need route
	string Filter, Filter0, Filter1;
	Filter0 = "(";
	Filter1 = "(";
	for (i = 0; i < IfCount; i++){
		Filter0 += "(ether dst " + MACntoa(IfInfo[i].MACAddr) + ")";
		for (j = 0; j < IfInfo[i].IP.size(); j++){
			Filter1 += "(ip dst host " + IPntoa(IfInfo[i].IP[j].IPAddr) + ")";
			if (((j == (IfInfo[i].IP.size() - 1))) && (i == (IfCount - 1)))	Filter1 += ")";
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
		pthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Capture, &IfInfo[i], 0, NULL);
	}

}



void AddRouter(string mask,string desIP,string nexthop){
	int i, j;
	DWORD ipaddr;
	RouteTable_t rt;
	ipaddr = htonl(inet_addr(nexthop.data()));

	for (i = 0; i < IfCount; i++){
		for (j = 0; j < IfInfo[i].IP.size(); j++){
			if (((IfInfo[i].IP[j].IPAddr)&(IfInfo[i].IP[j].IPMask)) == ((IfInfo[i].IP[j].IPMask)&ipaddr)){
				rt.IfNo = i;
				rt.Mask = inet_addr(mask.data());
				rt.DesIP = inet_addr(desIP.data());
				rt.NextHop = inet_addr(nexthop.data());
				RouteTable.push_back(rt);
			}
		}
	}
}

void DeleteRouter(string mask, string desIP, string nexthop){
	int i;
	char str[100], ipaddr[20];
	RouteTable_t rt;
	rt.Mask = inet_addr(mask.data());
	rt.DesIP = inet_addr(desIP.data());
	rt.NextHop = inet_addr(nexthop.data());

	list<RouteTable_t>::iterator it;
	for (it = RouteTable.begin(); it != RouteTable.end(); it++){
		if (it->Mask == rt.Mask && it->DesIP == rt.DesIP && it->NextHop == rt.NextHop){
			RouteTable.erase(it);
			return;
		}
	}

}


void listRouteTable(){
	int i;
	if (RouteTable.empty()){
		return;
	}
	list<RouteTable_t>::iterator rt;
	for (rt = RouteTable.begin(); rt != RouteTable.end();rt++){
		
		if (rt->NextHop == 0){
			cout << IPntoa(rt->DesIP) << "\t" << IPntoa(rt->Mask) << "\t" << "direct" << "\t" << rt->IfNo << endl;
		}
		else{
			cout << IPntoa(rt->DesIP) << "\t" << IPntoa(rt->Mask) << "\t" << IPntoa(rt->NextHop) << "\t" << rt->IfNo << endl;
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

int _tmain(int argc, _TCHAR* argv[])
{
	
	Logprint("Start");
	init();
	GetCmd();
	return 0;
}