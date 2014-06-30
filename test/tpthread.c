#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>

pthread_mutex_t mtx_ = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char* argv[])
{
	struct timeval begin, end;
	gettimeofday(&begin, NULL);
	volatile uint32_t count = 0;
	volatile uint32_t sum = 0;
	int a, b, c, d, e, f, g, h, i, j;
	a = b =c =d =e =f =g =h =i =j;
	int array[10] = {0};
	for (; count < 0xFFFFFFFF; ++count) {
		// sum += 1;
		//pthread_mutex_lock(&mtx_);
		//pthread_mutex_unlock(&mtx_);
		// a++; b++; c++; d++; e++; f++; g++; h++; i++; j++;
		// for (int n=0; n<10; ++n) { array[n]++; }
	}
	gettimeofday(&end, NULL);
	int total = a+ b+ c+ d+ e+ f+ g+ h+ i+ j;
	return 0;
}
