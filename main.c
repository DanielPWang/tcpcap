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

int DEBUG = 0;
const char* PCAPFILE = NULL;

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

void ProcessCMD(int argc, char* argv[])
{
	if (argc>1) {
		if (strcmp(argv[1],"-v")==0){
			ShowUsage(0);
		} else if (strcmp(argv[1], "-d")==0) {
			// TODO: debug
		} else if (strcmp(argv[1], "-r")==0) {
			DEBUG = 1;
			PCAPFILE = strdup(argv[2]);
			return;
		} else {
			ShowUsage(-1);
		}
		exit(2);
	}
}

void CheckRoot()
{
	if (DEBUG > 0) return;

	if (getuid() != 0) {
		fprintf(stderr, "You must be root\n");
		exit(3);
	}
}

void ProcessSIG()
{
	signal(SIGSEGV, sig_segv);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT,  sig_int);
	signal(SIGHUP,  SIG_IGN);
	signal(SIGUSR1, sig_usr);
}

int main(int argc, char* argv[])
{
	ShowVersion();
	ProcessCMD(argc, argv);
	CheckRoot();
	ProcessSIG();
	CONFIG_PATH = CONFIG_PATH_FILE;

	open_log("eru.log", GetValue_i(CONFIG_PATH, "loglevel"));
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

	// capture and process
	char* buffer = NULL; // = calloc(1,RECV_BUFFER_LEN);
	int nrecv = 0;
	
	while (Living) 
	{
		if (buffer == NULL) buffer = malloc( RECV_BUFFER_LEN); // TODO:
		if (buffer == NULL) { LOGWARN0("no memory!"); sleep(1); continue; }

		do 
		{
			nrecv = CapturePacket(buffer, RECV_BUFFER_LEN);
			if (nrecv == 0) continue;

			struct ether_header *ehead = (struct ether_header*)buffer;
			u_short eth_type = ntohs(ehead->ether_type); // TODO: stupid.
			if (ETHERTYPE_VLAN == eth_type) {			
				eth_type = ((u_char)buffer[16])*256 + (u_char)buffer[17];
			}
			
			if (ETHERTYPE_IP == eth_type) {
				struct iphdr *iphead = IPHDR(buffer);

				if (iphead->protocol == IPPROTO_TCP) {
					struct tcphdr *tcphead = TCPHDR(iphead);

					// Http filter.
					if (FilterPacketForHttp(buffer, iphead, tcphead) == 0) 
						break;
				}
			}
			buffer = NULL;
		} 
		while (Living);
	}
	LOGINFO0("ready to exit...");
	StopServer();
	LOGINFO0("exit server...");
	close_log();
	return 0;
}

