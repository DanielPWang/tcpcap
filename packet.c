#include <assert.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <glib-2.0/glib.h>
#include "packet.h"

packet_t* packet_new(void* buffer, uint32_t len)
{
	packet_t* p = (packet_head_t*)(malloc(sizeof(packet_head_t) + len-1));
	assert(p != NULL);
	memset(p, 0, sizeof(packet_t)-1);
	p->buffer_len = len;
	memcpy(p->buffer, buffer, len);
	return p;
}
bool packet_init(packet_t* phdr)
{
	struct ether_header *eth = (struct ether_header*)(phdr->buffer);
	if (eth->ether_type == 0x0008) {
		phdr->ip = (struct iphdr*)(phdr->buffer + ETHER_HDR_LEN);
	} else if (eth->ether_type == 0x0081) {
		if (phdr->buffer[16]==0x08 && phdr->buffer[17]==0x00) {
			phdr->ip = (struct iphdr*)(phdr->buffer + ETHER_HDR_LEN + 4);
		}
	}
	// not ip
	if (phdr->ip == NULL) return false;
	// not tcp
	if (phdr->ip->protocol != IPPROTO_TCP) return false;
	// dont support ipv6
	if (phdr->ip->version != 4) return false;
	phdr->tcp = (struct tcphdr*)((uint8_t*)(phdr->ip) + phdr->ip->ihl*4);
	phdr->content = (uint8_t*)(phdr->tcp) + phdr->tcp->doff*4;
	phdr->content_len = ntohs(phdr->ip->tot_len) - phdr->ip->ihl*4 - phdr->tcp->doff*4;
	assert(phdr->content_len < 1500);
	return true;
}
void packet_destory(packet_t* packet)
{
	free(packet);
}
/***************** packet_list **************************/
GList list_head = NULL;
GList list_end  = NULL;
GMutex list_mutex;

void packet_list_init()
{
	g_mutex_init(&list_mutex);
}
void packet_list_push(packet_t* p)
{
	if (list_head == list_end) {
		g_mutex_lock(&list_mutex);
		list_head = g_list_append(list_head, p);
		list_end = g_list_last(list_head);
		g_mutex_unlock(&list_mutex);
	} else {
		g_list_append(list_end, p);
		list_end = g_list_last(list_end);
	}
}
packet_t* packet_list_pop()
{
	packet_t* p = NULL;
	if (list_head == list_end) {
		if (list_head == NULL) {
		} else {
			g_mutex_lock(&list_mutex);
			p = (packet_t*)list_head.data;
			g_list_head = g_list_remove(g_list_head, p);
			assert(list_head == NULL);
			list_end = list_head;
			g_mutex_unlock(&list_mutex);
		}
	} else {
		p = (packet_t*)list_head.data;
		g_list_head = g_list_remove(g_list_head, p);
	}
	return p;
}

void packet_list_fini()
{
	g_mutex_lock(&list_mutex);
	g_mutex_unlock(&list_mutex);
	g_mutex_clear(&list_mutex);
}
