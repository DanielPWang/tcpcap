#ifndef __IFACE_H__
#define __IFACE_H__

typedef struct InterfaceFd 
{
	int nFd;
	char szInterface[10];  
} InterfaceFdDef;

int OpenMonitorDevs();

int CapturePacket(char* buffer, size_t size, int *nFdIndex);

#endif

