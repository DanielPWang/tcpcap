#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include <pthread.h>

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
#include <block.h>

static pthread_t _epoll_thread;
static pthread_t _capture_thread[MONITOR_COUNT];
int SockManager;
volatile int Living = 1;
volatile int NeedReloadConfig = 0;
int _net_flow_func_on = 0;
int _block_func_on = 0;

extern InterfaceFdDef g_arrayActiveFd[MONITOR_COUNT];
int g_nActiveFd[MONITOR_COUNT] = {0};
uint64_t g_nPreCapCount[MONITOR_COUNT] = {0};
uint64_t g_nCapCount[MONITOR_COUNT] = {0};
uint64_t g_nCapSize[MONITOR_COUNT] = {0};
uint64_t g_nValidCapCount[MONITOR_COUNT] = {0};
uint64_t g_nValidCapSize[MONITOR_COUNT] = {0};
uint32_t g_nCapFisrtTime = 0;
uint32_t g_nCapLastTime = 0;
extern uint64_t g_nSkippedPackCount;
extern uint32_t g_nThreadCount;
static int _thread_param[MONITOR_COUNT] = {0, 1, 2, 3, 4, 5, 6};
extern int _active_sock;
extern time_t g_nActiveSocketUpdateTime;
extern time_t g_nServerThreadUpdateTime;

const char *MonitorFilter;
const char* CONFIG_PATH;

void sig_int(int signo)
{
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
	printf("Version %d.%d.%d Copyright(C)2013\n",
			VER_MAJOR, VER_MINOR, VER_PATCH);
}

void ShowUsage(int nExit)
{
	printf("usage: ghcapture [-v]\n");
	printf("options:\n");
	printf("    -v show version.\n");
	exit(nExit);
}

void *capture_thread(void* param)
{
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	
	int nFdIndex = *(int*)param;

	g_nActiveFd[nFdIndex] = 1;
	char* buffer = NULL;
	int nrecv = 0;
	while (Living) 
	{
		buffer = calloc(1, RECV_BUFFER_LEN);
		if (buffer == NULL)
		{
			sleep(1);
			continue;
		}

		do 
		{
			nrecv = CapturePacket(nFdIndex, buffer, RECV_BUFFER_LEN);
			if (nrecv == 0)
			{
				//printf("CapturePacket size = 0, fdindex = %d!\n", nFdIndex);
				continue;
			}
			else if (nrecv < 0)
			{
				free(buffer);
				g_nPreCapCount[nFdIndex] = 0;
				g_nActiveFd[nFdIndex] = 0;
				ResetOneshot(nFdIndex);
				//printf("CapturePacket error, ResetOneshot, fdindex = %d!\n", nFdIndex);
				LOGERROR("CapturePacket error, ResetOneshot, fdindex = %d!", nFdIndex);
				return NULL;
			}

			++g_nCapCount[nFdIndex];
			g_nCapSize[nFdIndex] += nrecv;
			
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

				// Flow filter
				if (_net_flow_func_on)
					FilterPacketForFlow(iphead);

				if (iphead->protocol == IPPROTO_TCP)
				{
					struct tcphdr *tcphead = TCPHDR(iphead);

					// Http filter.
					if (FilterPacketForHttp(nFdIndex, buffer, nrecv, iphead, tcphead) == 0) 
						break;
				}
				else
				{
					g_nSkippedPackCount++;
				}
			}
			else
			{
				g_nSkippedPackCount++;
			}
			memset(buffer, 0, RECV_BUFFER_LEN);
		} while (Living);
	}

	return NULL;
}

void *epoll_thread(void* param)
{
	int nFdEventIndexArray[MONITOR_COUNT] = {0};
	while (Living) 
	{
		memset(nFdEventIndexArray, 0, MONITOR_COUNT*sizeof(int));
		int nFdCount = GetFdEvent(nFdEventIndexArray);
		if (nFdCount <= 0)
		{
			sleep(2);
			LOGERROR0("GetFdEvent error!\n");
			continue;
		}

		LOGINFO("GetFdEvent successfully! FdCount = %d", nFdCount);
		for (int i = 0; i < nFdCount; i++)
		{
			int nFdIndex = nFdEventIndexArray[i];
			LOGINFO("GetFdEvent, FdIndex = %d", nFdIndex);
			int err = pthread_create(&_capture_thread[nFdIndex], NULL, &capture_thread, &_thread_param[nFdIndex]);
			ASSERT(err == 0);
		}
	}

	return NULL;
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

	// init log
	char szLevel[10] = {0};
	GetValue(CONFIG_PATH, "loglevel", szLevel, 3);
	int nLevel = atoi(szLevel);
	open_all_log(nLevel);

	LOGFIX0("Start eru_agent...");
		
	// open monitordev
	if (OpenMonitorDevs() == 0) 
	{
		printf("Can Open any monitor!");
		LOGFATAL0("Can Open any monitor!");
		return 0;
	}

	// init protocol_proc
	HttpInit();

	// init net flow proc
	char szNetFlowFunc[10] = {0};
	GetValue(CONFIG_PATH, "net_flow_func", szNetFlowFunc, 6);
	if (strcmp(szNetFlowFunc, "true") == 0)
		_net_flow_func_on = 1;

	if (_net_flow_func_on)
		FlowInit();
	
	// start server
	g_nServerThreadUpdateTime = time(NULL);
	int nerr = StartServer();
	ASSERT(nerr == 0);

	// init block proc
	char szBlockFunc[10] = {0};
	GetValue(CONFIG_PATH, "block_func", szBlockFunc, 6);
	if (strcmp(szBlockFunc, "true") == 0)
		_block_func_on = 1;

	if (_block_func_on)
		InitBlockProc();

	int err = pthread_create(&_epoll_thread, NULL, &epoll_thread, NULL);
	ASSERT(err==0);
		
	time_t op_log_time = time(NULL);
	time_t session_timeout_proc_time = time(NULL);
	while (Living) 
	{
		if (0 == g_nCapFisrtTime)
			g_nCapFisrtTime = time(NULL);
		else
			g_nCapLastTime = time(NULL);

		/*
		if (ClientSocketIsValid())
		{
			if (time(NULL) - g_nActiveSocketUpdateTime > 40)
			{
				LOGWARN0("Active_socket_update_time do not update more than 40 seconds!Reboot server thread!");
				//printf("Active_socket_update_time do not update more than 40 seconds!Reboot server thread!");
				RebootServerThread();
			}
		}
		*/
		
		if (time(NULL) - g_nServerThreadUpdateTime > 40)
		{
			LOGWARN0("Server_thread_update_time do not update more than 40 seconds!Reboot server thread!");
			RebootServerThread();
		}
		
		if (time(NULL) - session_timeout_proc_time > SESSION_TIMEOUT_PROC_INTERVAL)
		{
			SessionTimeoutProcess();
			session_timeout_proc_time = time(NULL);
		}
		
		if (time(NULL) - op_log_time > LOG_OP_INTERVAL)
		{
			ShowOpLogInfo(0);
			op_log_time = time(NULL);

			for (int i = 0; i < _active_sock; i++)
			{
				if (1 == g_nActiveFd[i])
				{
					if (g_nCapCount[i] > 0)
					{
						if (g_nCapCount[i] == g_nPreCapCount[i])
						{
							LOGINFO("Capture if %s get no data for 5 minutes! Stop capture thread!", g_arrayActiveFd[i].szInterface);
							pthread_cancel(_capture_thread[i]);
							g_nPreCapCount[i] = 0;
							g_nActiveFd[i] = 0;
							ResetOneshot(i);
						}
						else
						{
							g_nPreCapCount[i] = g_nCapCount[i];
						}
					}
				}
			}
		}

		sleep(1);
	}

	ShowOpLogInfo(1);
	LOGFIX0("Ready to exit...");
	LOGFIX0("Stop Server Thread...");
	StopServer();
	LOGFIX0("Stop Http Thread...");
	StopHttpThread();
	CloseCacheFile();
	LOGFIX0("Exit eru_agent...");
	close_all_log();

	return 0;
}

