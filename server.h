#ifndef __SERVER_H__
#define __SERVER_H__

#define MSG_NORMAL_VER 0x01
#define MSG_TYPE_HEARTHIT 0x00
#define MSG_TYPE_NOTIFY_CONNECTION_EXIST  0x01
#define MSG_TYPE_HTTP  0x10

#define MSG_TYPE_REQ_GET_IPLIST 0x20
#define MSG_TYPE_REQ_SET_IPLIST 0x21
#define MSG_TYPE_RES_IPLIST 0x40

#define MSG_TYPE_REQ_FLOW 0x22
#define MSG_TYPE_REQ_FLOW_STOP 0x23
#define MSG_TYPE_RES_FLOW_SERVER_COUNT 0x41
#define MSG_TYPE_RES_FLOW_DATA 0x42

#define MSG_TYPE_RES_OK 0xFF

#define CLIENT_SOCKET_PORT 22012
#define CLIENT_SOCKET_PORT_MIN 20001
#define CLIENT_SOCKET_PORT_MAX 20020
#define CLIENT_CONFIG_SOCKET_PORT 22013
#define CLIENT_TEST_SOCKET_PORT 22014
#define CLIENT_FLOW_SOCKET_PORT 22015

#define SELECT_TIMEOUT 30000

struct msg_head
{
	unsigned char version;
	unsigned char type;
	unsigned int  length;
}__attribute__((packed));

int InitServer();
int StartServer();
void StopServer();

#endif

