#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <iface.h>
#include <utils.h>
#include <define.h>
#include <config.h>

static int _epollfd = 0;
static struct epoll_event _events[MONITOR_COUNT];
int _active_sock = 0;
InterfaceFdDef g_arrayActiveFd[MONITOR_COUNT];

int get_iface_id(int fd, const char* device)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		perror("[ERROR] ");
		return -1;
	}
	return ifr.ifr_ifindex;
}

int active_device(int fd, const char* device)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
		perror("[ERROR] ");
		return -1;
	}
	ifr.ifr_flags |= IFF_PROMISC;
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
		perror("[ERROR] ");
		return -1;
	}
	return 0;
}

int open_monitor(const char* interface, const char* fliter)
{
	struct sockaddr_ll sall = {0};

	int fd = socket(PF_PACKET, SOCK_RAW, htons(IPPROTO_TCP));
	if (fd < 0) {
		perror("[ERROR] ");
		return -1;
	}

	sall.sll_family = AF_PACKET;
	sall.sll_protocol = htons(ETH_P_ALL);
	sall.sll_ifindex = get_iface_id(fd, interface);
	if (bind(fd, (struct sockaddr*)&sall, sizeof(sall)) == -1) {
		perror("[ERROR] ");
		close(fd);
		return -1;
	}

	if (active_device(fd, interface) == -1) {
		LOGERROR0("Fail to active device");
		close(fd);
		return -1;
	}
		
	return fd;
}

int OpenMonitorDevs()
{
	char* value = (char*)calloc(1,1024);
	ASSERT(value!=NULL);
	if (GetValue(CONFIG_PATH, "monitor", value, 1024)==NULL || value[0]=='\0') {
		LOGFATAL("Can not get monitor info from %s", CONFIG_PATH);
		abort();
	}

	ASSERT(_epollfd==0);
	ASSERT(_active_sock == 0);
	memset(g_arrayActiveFd, 0, sizeof(InterfaceFdDef)*MONITOR_COUNT);
	_epollfd = epoll_create(MONITOR_COUNT);
	ASSERT(_epollfd!=-1);
	struct epoll_event ev;

	int nCurFd = 0;
	char *left = value;
	char *right = NULL;
	for (; _active_sock<=MONITOR_COUNT ; left=NULL)
	{
		left = strtok_r(left, " ", &right);
		if (left == NULL) 
			break;
		
		nCurFd = open_monitor(left, "");
		if (nCurFd > 0) 
		{
			strcpy(g_arrayActiveFd[_active_sock].szInterface, left);
			g_arrayActiveFd[_active_sock].nFd = nCurFd;
			LOGINFO("open interface %s", left);
			ev.events = EPOLLIN | EPOLLONESHOT;
			ev.data.fd = g_arrayActiveFd[_active_sock].nFd;
			if (epoll_ctl(_epollfd, EPOLL_CTL_ADD, g_arrayActiveFd[_active_sock].nFd, &ev)==-1) 
			{
				perror("[ERROR] ");
			}
			++_active_sock;
		} 
		else 
		{
			LOGINFO("cannt open interface %s", left);
		}
	}
	free(value);
	return _active_sock;
}

void ResetOneshot(int nFdIndex)
{
    struct epoll_event event;  
    event.data.fd = g_arrayActiveFd[nFdIndex].nFd;
    event.events = EPOLLIN | EPOLLONESHOT;  
    if (epoll_ctl(_epollfd, EPOLL_CTL_MOD, g_arrayActiveFd[nFdIndex].nFd, &event) == -1)
    {
		LOGERROR0("ResetOneshot error!");
	}
}  

int GetFdEvent(int *pFdEventIndexArray)
{
	assert(_epollfd > 0);
	assert(_active_sock > 0);
	assert(pFdEventIndexArray != NULL);

	int nfds = epoll_wait(_epollfd, _events, _active_sock, -1);
	if (nfds < 1) 
	{
		return -1;
	}

	int nIndex = 0;
	for (int i = 0; i < nfds; i++)
	{
		int nFd = _events[i].data.fd;
		for (int j = 0; j < _active_sock; j++)
		{
			if (nFd == g_arrayActiveFd[j].nFd)
			{
				pFdEventIndexArray[nIndex++] = j;
			}
		}
	}
	
	return nIndex;
}

int CapturePacket(int nFdIndex, char* buffer, size_t size)
{
	struct sockaddr_in sa;
	size_t salen = sizeof(sa);

	int nRecv = recvfrom(g_arrayActiveFd[nFdIndex].nFd, buffer, size, 0,
							(struct sockaddr*)&sa, &salen);

	if(nRecv < 0)
	{	
		LOGERROR("CapturePacket error! errno=[%d] %s", errno, strerror(errno));
	} 
	
	return nRecv;
}

void CloseOpenMonitorDevs()
{
	for (; _active_sock>0; --_active_sock) {
		if (epoll_ctl(_epollfd, EPOLL_CTL_DEL, g_arrayActiveFd[_active_sock-1].nFd, NULL) == -1) {
			perror("[ERROR] ");
		}
	}
	close(_epollfd);
	_epollfd = 0;
}

