#ifndef __CONFIG_H__
#define __CONFIG_H__

#define BUFFER_MAX_LEN 1024
/**
 * @brief get value of name from confname.
 * @note  
 */
char* GetValue(const char* confname, const char* name, char* value, size_t len);
int GetValue_i(const char* confname, const char* name);
int GetFileData(const char* pszFileName, char* pszFileData, int nMaxLen);

#define VERSION "1.0.1"

#define config_file "conf/http.conf"
#define config_file "conf/hosts
#define max_ip_count 100
#define max_session_count 2000
#define max_session_timeout 30
#define max_packet_count 0

#define LOG_DEBUG(fmt, ...) \
	do { if (log_level <= LOG_DEBUG)syslog( LOG_DEBUG, fmt, "[%s:%d]" fmt, __FILE__, __LINE__, ##__VA_ARGS__ ); } while (0);
#define LOG_INFO(fmt, ...) \
	do { if (log_level <= LOG_INFO)syslog( LOG_DEBUG, fmt, "[%s:%d]" fmt, __FILE__, __LINE__, ##__VA_ARGS__ ); } while (0);
#define LOG_WARN(fmt, ...) \
	do { if (log_level <= LOG_WARNING)syslog( LOG_DEBUG, fmt, "[%s:%d]" fmt, __FILE__, __LINE__, ##__VA_ARGS__ ); } while (0);
#define LOG_ERROR(fmt, ...) \
	do { if (log_level <= LOG_ERR)syslog( LOG_DEBUG, fmt, "[%s:%d]" fmt, __FILE__, __LINE__, ##__VA_ARGS__ ); } while (0);
#endif

