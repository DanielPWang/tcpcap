#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

extern volatile int Living;

 uint32_t total_pcap = 0u;
 uint32_t packets_pushed = 0u;
 uint32_t packets_pop = 0u;
 uint32_t sent_count = 0u;
 uint32_t whole_html_session = 0u;

#define P(x) printf("\t" #x " = %u\n", x)
void PrintStatis()
{
	P(total_pcap);
	P(packets_pushed);
	P(packets_pop);
	P(sent_count);
	P(whole_html_session);
}
void PrintTitle()
{
	printf("CAP\tPKTSIN\tPKTSOUT\tSEND\tWHOLE\n");
}
void PrintStati()
{
	printf("%u\t%u\t%u\t%u\t%u\t\n", total_pcap, packets_pushed, packets_pop,
			sent_count, whole_html_session);
}
void* _show_statis_thread(void* p)
{
	PrintTitle();
	while (Living) {
		PrintStati();
		int err = sleep(5);
	}
	return NULL;
}
void StartShowStatis()
{
	pthread_t pid;
	pthread_create(&pid, NULL, _show_statis_thread, NULL);
}
