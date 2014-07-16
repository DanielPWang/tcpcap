#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/time.h>
#include <atomic_ops.h>
#include "fall.h"

pthread_mutex_t mtx_ = PTHREAD_MUTEX_INITIALIZER;

struct A {
	int a, b;
};

typedef struct A b;

int main(int argc, char* argv[])
{
	struct sched_param sch; 
	if (sch.__sched_priority = sched_get_priority_max(SCHED_FIFO) < 0) {
		perror("ERROR:1");
		return -1;
	}
	if (sched_getscheduler(getpid()) < 0) {
		perror("ERROR:0");
		return -1;
	}
	printf("MIN: %d MAX: %d\n", sched_get_priority_min(SCHED_FIFO), sched_get_priority_max(SCHED_FIFO));
	sch.__sched_priority = (sched_get_priority_min(SCHED_FIFO)+sched_get_priority_max(SCHED_FIFO))/2;
	if (sched_setscheduler(getpid(), SCHED_FIFO, &sch) < 0){
		perror("ERROR: ");
		return -1;
	}
	struct timeval begin, end;
	gettimeofday(&begin, NULL);
	uint32_t count = 0;
	volatile uint32_t sum = 0;
	int a, b, c, d, e, f, g, h, i, j;
	a = b =c =d =e =f =g =h =i =j;
	int array[10] = {0};
	AO_t A = AO_TS_INITIALIZER;
	for (; count < 0xFFFFFFFF; ++count) {
		//AO_fetch_and_add1(&A);
		// sum += 1;
		//pthread_mutex_lock(&mtx_);
		//pthread_mutex_unlock(&mtx_);
		// a++; b++; c++; d++; e++; f++; g++; h++; i++; j++;
		// for (int n=0; n<10; ++n) { array[n]++; }
	}
	gettimeofday(&end, NULL);
	int total = a+ b+ c+ d+ e+ f+ g+ h+ i+ j;
	printf("%u %u\n", A, sizeof(struct http_sessions_t)*65535);
	return 0;
}
