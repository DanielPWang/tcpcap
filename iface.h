#ifndef __IFACE_H__
#define __IFACE_H__

typedef struct InterfaceFd 
{
	int nFd;
	char szInterface[10];  
} InterfaceFdDef;

int OpenMonitorDevs();

void ResetOneshot(int nFdIndex);
int GetFdEvent();
int CapturePacket(int nFdIndex, char* buffer, size_t size);

#endif

