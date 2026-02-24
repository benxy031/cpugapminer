#pragma once
#include <string>
#include <sstream>
#include <curl/curl.h>
#include <pthread.h>
#include <stdint.h>

class BlockHeader {
public:
    BlockHeader(const std::string *s);
    std::string get_hex() const;
    uint64_t target;
private:
    std::string hex;
};

class Rpc {
public:
    struct LongPoll { bool supported; std::string url; LongPoll(): supported(false) {} };

    static pthread_mutex_t send_mutex;
    static pthread_mutex_t creation_mutex;
    static Rpc *only_instance;
    static bool initialized;
    static bool curl_initialized;
    static int timeout;
    static LongPoll longpoll;
    static std::string server_url;
    static std::stringstream *recv_ss;
    static CURL *curl_recv;
    static CURL *curl_send;
    static std::string getwork_rpccmd;

    static Rpc *get_instance();
    static bool init_curl(std::string userpass, std::string url, int timeout);

    Rpc();
    ~Rpc();

    BlockHeader *getwork(bool do_lp);
    bool sendwork(BlockHeader *header);
};
