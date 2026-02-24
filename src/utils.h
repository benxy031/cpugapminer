#pragma once
#include <string>
#include <pthread.h>

#define LOG_D 0
#define LOG_W 1

void log_str(const std::string &s, int level);
void extra_verbose_log(const std::string &s);
std::string get_time();
std::string itoa(int v);

#ifndef USER_AGENT
#define USER_AGENT "gapminer"
#endif

extern pthread_mutex_t io_mutex; // use pthread_mutex_t for Rpc.cpp

// minimal implementations for log helpers used by Rpc.cpp (if linked into C++)
inline void log_str(const std::string &s, int level) {
	(void)level;
	fprintf(stderr, "%s\n", s.c_str());
}
inline void extra_verbose_log(const std::string &s) { fprintf(stderr, "%s\n", s.c_str()); }
inline std::string get_time() { return ""; }
inline std::string itoa(int v) { char b[32]; snprintf(b,sizeof(b),"%d",v); return std::string(b); }
