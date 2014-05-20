#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <pthread.h>

#include <utils.h>
#include <shmutil.h>

struct _data
{
	struct _data* next;
	char data[];
};

struct _shm
{
	int id;
	size_t size;
	void *addr;
	struct _data *head;
	struct _data *_head;
	struct _data *tail;
	pthread_mutex_t lock;
};

const int _remain_size = sizeof(struct _shm);

void* InitSharemem(const char* name, size_t size)
{
	if (size < 4096) size=4096;

	key_t key = IPC_PRIVATE;
	if (name != NULL) key = ftok(name, 0x0808);
	if (key == -1) return NULL;

	// TODO: 此处应该作多进程处理
	struct _shm *shm = (struct _shm*)calloc(1,sizeof(*shm));
	if (shm == NULL) return NULL;

	if (pthread_mutex_init(&shm->lock, NULL)==0) {
		shm->id = shmget(key, size, IPC_CREAT|SHM_NORESERVE);
		if (shm->id > -1) {
			shm->addr = shmat(shm->id, NULL, 0);
			if (shm->addr != (void*)-1) {
				shm->head = shm->tail = (struct _data*)shm->addr;
				shm->_head = NULL;
				return shm;
			}
			// dont destory shm.
		}
	}
	free(shm);
	return NULL;
}

char* GetBuffer(void *shm, size_t size)
{
	size += sizeof(struct _data);
	if (size%sizeof(void*)>0) { size += (sizeof(void*) - size%sizeof(void*)); }

	struct _shm *p = (struct _shm*)shm;
	if (size >= p->size) {
		LOGERROR("require %u, but have %u", size, p->size);
		return NULL;
	}
	pthread_mutex_lock(&p->lock);
	if ((void*)p->head+size > p->addr+p->size) {
		while(p->tail > p->head && p->tail<=(p->head+size)) {
			LOGWARN("%s", "drop a packet.");
			p->tail = p->tail->next;
			if (p->tail == NULL) p->tail = (struct _data*)p->addr;
		}
		if (p->tail == p->addr) p->tail = p->tail->next;
		p->head->next = NULL;
		p->head = (struct _data*)p->addr;
	}
	if ((void*)p->head+size <= p->addr+size) {
		// B..T_______H...,...E  or B___H...,...T___E
		if (p->head>p->tail || ((void*)p->head+size<(void*)p->tail)) {
			p->head->next = (void*)p->head + size;
			p->head = p->head->next;
		} else { // B___H..T__,__E
			while ((void*)p->tail <= (void*)p->head+size) {
				if (p->tail < p->head) break;	// B.T__H..,..E
				LOGWARN("%s", "drop some datas.");
				p->tail = p->tail->next;
				if (NULL == p->tail) p->tail=(struct _data*)p->addr;
			}
			p->head->next = (void*)p->head + size;
			p->head = p->head->next;
		}
	}
	void* buffer = &p->head->data[0];
	p->head->next = NULL;
	pthread_mutex_unlock(&p->lock);
	return buffer;
}

// have bug
const char* GetData(void *shm, void *data, int *len)
{
	struct _shm *p = (struct _shm*)shm;

	if (p->head==p->tail && p->head->next==NULL) {
		*len = 0;
		return NULL;
	}
	pthread_mutex_lock(&p->lock);
	if (p->head==p->tail && p->head->next==NULL) {
		*len = 0;
	} else {
		memcpy(data, p->tail, *len);
		p->tail = p->tail->next;
		if (NULL == p->tail) p->tail = (struct _data*)p->addr;
	}
	pthread_mutex_unlock(&p->lock);
	return *len==0? NULL:data;
}

void DestorySharemem(void* shm)
{
	struct _shm *p = (struct _shm*)shm;
	shmdt(p->addr);
	free(shm);
}
