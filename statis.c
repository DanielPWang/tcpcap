#include <stdint.h>
#include <stdio.h>

static uint64_t total_pcap = 0u;
static uint64_t packets_pushed = 0u;
static uint64_t packets_pop = 0u;

void PrintStatis()
{
	printf("\ttotal_pcap = %u\n", total_pcap);
	printf("\tpackets_pushed = %u\n", packets_pushed);
	printf("\tpackets_pop= %u\n", packets_pop);
}
