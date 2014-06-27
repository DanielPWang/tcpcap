#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>

pthread_mutex_t mtx_ = PTHREAD_MUTEX_NORMAL;

int main(int argc, char* argv[])
{
	struct timeval begin, end;
	gettimeofday(&begin, NULL);

	gettimeofday(&end, NULL);
	return 0;
}
