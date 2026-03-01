/* compat_win32.h — Windows (MinGW/MSVC) compatibility shims
 *
 * Include this header early in any source file that uses POSIX socket APIs,
 * usleep/nanosleep, clock_gettime, getpid, or /tmp paths.
 *
 * On Linux/POSIX this header is a no-op.
 */
#ifndef COMPAT_WIN32_H
#define COMPAT_WIN32_H

#ifdef _WIN32

/* ── Winsock2 ── */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <process.h>          /* _getpid() */

/* Link against ws2_32 (handled by Makefile -lws2_32 for MinGW,
   or #pragma comment for MSVC). */
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32")
#endif

/* ── socket compat ── */
typedef SOCKET sock_t;
#define SOCK_INVALID    INVALID_SOCKET
#define sock_close(s)   closesocket(s)
#define sock_errno()    WSAGetLastError()

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0        /* not needed on Windows */
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif

/* ssize_t is not defined by MSVC; MinGW provides it via sys/types.h,
   but define it here as a fallback. */
#ifndef _SSIZE_T_DEFINED
#ifndef __MINGW32__
typedef intptr_t ssize_t;
#define _SSIZE_T_DEFINED
#endif
#endif

/* ── getpid ── */
#ifndef getpid
#define getpid()  _getpid()
#endif

/* ── nanosleep ── */
/* MinGW winpthreads already provides nanosleep via pthread_time.h.
   Only define our fallback for MSVC or if it's genuinely missing. */
#if defined(_MSC_VER) || (!defined(__MINGW32__) && !defined(HAVE_NANOSLEEP))
static inline int nanosleep(const struct timespec *req, struct timespec *rem) {
    (void)rem;
    DWORD ms = (DWORD)(req->tv_sec * 1000 + req->tv_nsec / 1000000);
    if (ms == 0 && req->tv_nsec > 0) ms = 1;
    Sleep(ms);
    return 0;
}
#endif

/* ── sleep() ── */
#ifndef sleep
#define sleep(s)  Sleep((DWORD)(s) * 1000)
#endif

/* ── clock_gettime ── */
/* MinGW winpthreads already provides clock_gettime via pthread_time.h.
   Only define our fallback for MSVC or if genuinely missing. */
#if defined(_MSC_VER) || (!defined(__MINGW32__) && !defined(CLOCK_REALTIME))
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif
static inline int clock_gettime(int clk_id, struct timespec *ts) {
    (void)clk_id;
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    /* FILETIME is 100ns intervals since 1601-01-01.
       Subtract epoch offset (11644473600 seconds). */
    uint64_t ns100 = uli.QuadPart - 116444736000000000ULL;
    ts->tv_sec  = (time_t)(ns100 / 10000000ULL);
    ts->tv_nsec = (long)((ns100 % 10000000ULL) * 100);
    return 0;
}
#endif

/* ── gettimeofday ── */
#ifndef HAVE_GETTIMEOFDAY
struct timeval;  /* forward decl — windows.h may or may not include winsock2 */
static inline int gettimeofday(struct timeval *tv, void *tz) {
    (void)tz;
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    uint64_t us = (uli.QuadPart - 116444736000000000ULL) / 10;
    tv->tv_sec  = (long)(us / 1000000ULL);
    tv->tv_usec = (long)(us % 1000000ULL);
    return 0;
}
#endif

/* ── Temp directory ──
   On Windows, use %TEMP% (usually C:\Users\...\AppData\Local\Temp).
   Returns a trailing-backslash path. */
static inline const char *win_temp_dir(void) {
    static char buf[MAX_PATH + 1];
    if (!buf[0]) {
        DWORD n = GetTempPathA(MAX_PATH, buf);
        if (n == 0 || n > MAX_PATH)
            strcpy(buf, ".\\");
    }
    return buf;
}

/* Winsock initialisation — call once from main(). */
static inline void win_wsa_init(void) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
}
static inline void win_wsa_cleanup(void) {
    WSACleanup();
}

#else /* ── POSIX ── */

#include <unistd.h>
#include <sys/time.h>

typedef int sock_t;
#define SOCK_INVALID    (-1)
#define sock_close(s)   close(s)
#define sock_errno()    errno

/* No special init needed on POSIX */
static inline void win_wsa_init(void) {}
static inline void win_wsa_cleanup(void) {}

/* On POSIX, /tmp is fine */
static inline const char *win_temp_dir(void) { return "/tmp/"; }

#endif /* _WIN32 */

#endif /* COMPAT_WIN32_H */
