#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <utils.h>
#include <iface.h>
#include <config.h>
#include <fun_http.h>
#include <server.h>
#include "define.h"

int SockManager;
extern int SockMonitor[MONITOR_COUNT];
size_t MemorySize;
volatile int Living = 1;
volatile int NeedReloadConfig = 0;

extern uint64_t g_CapCount;
extern uint64_t g_CapSize;
extern uint32_t g_nCapFisrtTime;
extern uint32_t g_nCapLastTime;


const char *MonitorFilter;
const char* CONFIG_PATH;

void sig_int(int signo)
{
	LOGINFO0("Recv signal to exit...");
	Living = 0;
}

void sig_segv(int signo)
{
	print_bt();
	exit(-1);
}

void sig_usr(int signo)
{
	NeedReloadConfig = 1;
}

int LoadConfig(const char* confPath)
{
	NeedReloadConfig = 0;
	return 1;
}


void ShowVersion()
{
	printf("Version %d.%d.%d (%d) Copyright(C)2012\n",
			VER_MAJOR, VER_MINOR, VER_PATCH, VER_SVNID);
}

void ShowUsage(int nExit)
{
	printf("usage: ghcapture [-v]\n");
	printf("options:\n");
	printf("    -v show version.\n");
	exit(nExit);
}

int main(int argc, char* argv[])
{
	// process params
	ShowVersion();
	if (argc>1) {
		if (strcmp(argv[1],"-v")==0){
		ShowUsage(0);
		} else {
		ShowUsage(-1);
		}
	}

	// check root
	if (getuid() != 0) {
		fprintf(stderr, "You must be root\n");
		return -1;
	}

	// signal somethings
	signal(SIGSEGV, sig_segv);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT,  sig_int);
	signal(SIGHUP,  SIG_IGN);
	signal(SIGUSR1, sig_usr);

	// config_file
	char* conf_file = calloc(1,256);
	strcpy(conf_file, argv[0]);
	strcat(dirname(conf_file), CONFIG_PATH_FILE);
	CONFIG_PATH = conf_file;

	// log
	{
		char* tmp = calloc(1,1024);
		ASSERT(tmp!=NULL);
		char* logfile=tmp;
		char* loglevel=tmp+1000;

		GetValue(CONFIG_PATH, "logfile", logfile, 1000);
		GetValue(CONFIG_PATH, "loglevel", loglevel, 24);
		int nlevel = atoi(loglevel);
		open_log(logfile, nlevel);
		free(tmp);
	}
	// open monitordev
	if (OpenMonitorDevs() == 0) {
		LOGFATAL("%s", "Can Open any monitor.");
		return 0;
	}
	// start server
	int nerr = StartServer();
	ASSERT(nerr == 0);
	// init protocol_proce
	LoadHttpConf(CONFIG_PATH);
	HttpInit();

	FlowInit();

	// capture and process
	char* buffer = NULL; // = calloc(1,RECV_BUFFER_LEN);
	int nrecv = 0;
	
	while (Living) 
	{
		buffer = calloc(1, RECV_BUFFER_LEN); // GetBuffer(shmptr);
		if (buffer == NULL)
		{
			sleep(1);
			continue;
		}

		do 
		{
			nrecv = CapturePacket(buffer, RECV_BUFFER_LEN);
			if (nrecv == 0) 
				continue;

			++g_CapCount;
			g_CapSize += nrecv;
			
			if (0 == g_nCapFisrtTime)
				g_nCapFisrtTime = time(NULL);
			else
				g_nCapLastTime = time(NULL);
			
					
			struct ether_header *ehead = (struct ether_header*)buffer;
			u_short eth_type = ntohs(ehead->ether_type);
			if (ETHERTYPE_VLAN == eth_type)
			{
			
				eth_type = ((u_char)buffer[16])*256 + (u_char)buffer[17];
				//LOGDEBUG("vlan packet, eth_type = %x", eth_type);
				//fprintf(stderr, "vlan packet, eth_type = %x \n", eth_type);
			}
			
			if (ETHERTYPE_IP == eth_type)
			{
				struct iphdr *iphead = IPHDR(buffer);

				/*
				struct in_addr sip; 
				struct in_addr dip; 
		
				sip.s_addr = iphead->saddr;
				dip.s_addr = iphead->daddr;
				char ssip[16], sdip[16];
				fprintf(stderr, "%s => %s \n", strcpy(ssip, inet_ntoa(sip)), strcpy(sdip,inet_ntoa(dip)));
				*/
				
				// Flow filter
				FilterPacketForFlow(iphead);
				if (iphead->protocol == IPPROTO_TCP)
				{
					struct tcphdr *tcphead = TCPHDR(iphead);

					// Http filter.
					if (FilterPacketForHttp(buffer, iphead, tcphead) == 0) 
						break;
				}
			}
			memset(buffer, 0, RECV_BUFFER_LEN);
		} 
		while (Living);
	}
	ShowLastLogInfo();
	LOGINFO0("ready to exit...");
	StopServer();
	LOGINFO0("exit server...");
	close_log();
	return 0;
}

