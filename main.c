#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <pcap.h>
#include <syslog.h>
#include <glib-2.0/glib.h>

#include "config.h"
#include "packet.h"
#include "ipset.h"

static char pcap_errbuf[PCAP_ERRBUF_SIZE];
const char* monitor_interface = "eth1";
const char* pcap_filter_string = "tcp portrange 80-90 or portrange 8080-8100 or ( vlan and tcp portrange 80-90 or portrange 8080-8100)";
const char* center = "10.10.100.98:8088";
static pcap_t *pcap_handle = NULL;
static pkt_queue_t* packet_queue = NULL;

void sig_int(int signo)
{
	pcap_breakloop(pcap_handle);
}

void pcap_process(u_char *user, const struct pcap_pkthdr *h, const u_char* bytes)
{
	if (h->caplen != p->len) {
		LOG_ERROR("caplen=%u len=%u. drop\n", h->caplen, p->len);
		return;
	}
	packet_head_t* p = packet_new(bytes, h->caplen);
	p->recv_time = h->ts;
	pkt_queue_push((pkt_queue_t*)user, p);
}

void load_from_config(const char* file)
{
	ipset_load_from_file(config_file);
}

int main(int argc, char* argv[])
{
	printf("http pcap %s\n", VERSION);

	packet_queue = pkt_queue_new();
	load_from_config(config_file);
	pcap_handle = pcap_open_live(monitor_interface, 65535, 1, -1, pcap_errbuf);

	if (pcap_handle == NULL) {
		LOG_ERROR("Cannt open '%s': %s\n", monitor_interface, pcap_errbuf);
		return -1;
	}

	struct bpf_program bpf;
	if (pcap_compile(pcap_handle, &bpf, pcap_filter_string, 1, PCAP_NETMASK_UNKNOWN)==-1
			&& pcap_setfilter(pcap_handle, &bpf)==-1 ) {
		LOG_ERROR("Cannt set filter: '%s'\n", pcap_filter_string);
		pcap_close(pcap_handle);
		return -1;
	}

	pcap_dispatch(pcap_handle, -1, pcap_process, (u_char*) packet_queue);

	pcap_close(pcap_handle);

	return 0;
}

