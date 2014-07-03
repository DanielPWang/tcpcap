///////////////////////////////////////////////
static struct http_sessions_t* _http_sessions = NULL;
typedef struct http_sessions_t* HttpSessions;
int http_sessions_init()
{
	ASSERT(_http_sessions == NULL);
	_http_sessions = (struct http_sessions_t*)malloc(65536*sizeof(struct http_sessions_t));
	if (_http_sessions == NULL) return -1;
	for (int n=0; n<65536; ++n) {
		_http_sessions[n].head = NULL;
		pthread_mutex_init(&_http_sessions[n].lock, NULL);
		_http_sessions[n].used = 0;
	}
	return 0;
}
HttpSessions http_sessions_get(struct hosts_t* host)
{
	uint16_t index = (uint16_t)host->ip.s_addr;
	index = ~index;
	index ^= host->port;
	return &_http_sessions[index];
}
inline struct tcp_session* http_sessions_first(HttpSessions sessions)
{
	return sessions->head;
}
struct tcp_session* http_sessions_add_new(HttpSessions sessions, const struct tcp_session* Session)
{
	struct tcp_session* session = (struct tcp_session*)Session;
	pthread_mutex_lock(&sessions->lock);
	++sessions->used;
	if (sessions->head != NULL) {
		sessions->head->prev= session;
	}
	session->next = sessions->head;
	assert(session->prev = NULL);
	sessions->head = session;
	pthread_mutex_unlock(&sessions->lock);
	return session;
}
struct tcp_session* http_sessions_del(HttpSessions sessions, const struct tcp_session* Session)
{
	struct tcp_session* session = (struct tcp_session*)Session;
	pthread_mutex_lock(&sessions->lock);
	if (session->prev!=NULL) {
		session->prev->next = session->next;
	} else {
		sessions->head = session->next;
		sessions->head->prev = NULL;
	}
	pthread_mutex_unlock(&sessions->lock);
	return session;
}
void http_sessions_destory()
{
	for (int n=0; n<65536; ++n) {
		pthread_mutex_destroy(&_http_sessions[n].lock);
	}
	free(_http_sessions);
	_http_sessions = NULL;
}
