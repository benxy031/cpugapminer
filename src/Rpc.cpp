/**
 * Implementation of GapMiners rpc interface to gapcoind
 *
 * Copyright (C)  2014  The Gapcoin developers  <info@gapcoin.org>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __STDC_FORMAT_MACROS 
#define __STDC_FORMAT_MACROS 
#endif
#ifndef __STDC_LIMIT_MACROS  
#define __STDC_LIMIT_MACROS  
#endif
#include "Rpc.h"
#include <jansson.h>
#include "utils.h"
#include "Opts.h"
#include <cstring>
#include <iostream>

using namespace std;

/* synchronization mutexes */
pthread_mutex_t Rpc::send_mutex     = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t Rpc::creation_mutex = PTHREAD_MUTEX_INITIALIZER;


/* this will be a singleton */
Rpc *Rpc::only_instance = NULL;

/* indicates if this was initialized */
bool Rpc::initialized = false;

/* indicates if curl was initialized */
bool Rpc::curl_initialized = false;

/* rpc timeout */
int Rpc::timeout = 5;

/* the LongPoll object of this */
Rpc::LongPoll Rpc::longpoll = Rpc::LongPoll();

/* server url */
string Rpc::server_url = "";

/* string stream for receiving */
stringstream *Rpc::recv_ss = new stringstream;

/* curl receive session handle */
CURL *Rpc::curl_recv = NULL;

/* curl send session handle */
CURL *Rpc::curl_send = NULL;


/* get work rpc command */
string Rpc::getwork_rpccmd = "{\"jsonrpc\": \"1.0\", "
                             "\"id\":\"" USER_AGENT "\", "
                             "\"method\": \"getwork\", "
                             "\"params\": [] }";

/**
 * curl callback function to send rpc commands to the server
 */
size_t curl_read(void *ptr, size_t size, size_t nmemb, void *user_data) {

  static unsigned int pos = 0;
  string *rpccmd = (string *) user_data;
  unsigned int len = rpccmd->length();

  if (pos < len) {
    unsigned int bytes = (size * nmemb >= len - pos) ? len - pos : size * nmemb;
    log_str(string("curl_read: \"") + string(rpccmd->c_str() + pos, bytes) + "\"", LOG_D);
    memcpy(ptr, rpccmd->c_str() + pos, bytes);
    
    pos += bytes;
    return bytes;
  }
  
  pos = 0;
  return 0;
}

/**
 * curl callback function to receive rpc responses from the server
 */
size_t curl_write(char *ptr, size_t size, size_t nmemb, void *user_data) {
  stringstream *ss = (stringstream *) user_data;
  
  if ((size * nmemb) > 0) {
    log_str(string("curl_write: \"") + string(ptr, size * nmemb) + "\"", LOG_D);
    ss->write(ptr, size * nmemb);
  }

  return size * nmemb;
}

/**
 * curl callback function for receive the http header
 */
size_t curl_header(char *ptr, size_t size, size_t nmemb, void *user_data) {

  log_str(string("curl_header: \"") + string(ptr, size * nmemb) + "\"", LOG_D);
  static string lp_str("X-Long-Polling: ");
  Rpc::LongPoll *longpoll = (Rpc::LongPoll *) user_data;

  string str(ptr, size * nmemb);
  size_t start = str.find(lp_str);

  if (start != string::npos && start < nmemb * size - lp_str.length()) {
    start += lp_str.length();

    size_t end = str.find("\r\n", start);
    if (end != string::npos && end < nmemb * size) {
        longpoll->supported = true;
        longpoll->url = str.substr(start, end - start);
    }
  }

  return size * nmemb;
}

/**
 * initialize curl with the given 
 * username, password, url and port
 */
bool Rpc::init_curl(string userpass, string url, int timeout) {

  log_str(string("init curl with timeout: ") +  itoa(timeout), LOG_D);
  curl_global_init(CURL_GLOBAL_ALL);

  curl_recv = curl_easy_init();
  curl_send = curl_easy_init();
  if(curl_recv && curl_send) {
    curl_easy_setopt(curl_recv, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_recv, CURLOPT_ENCODING, "");
    curl_easy_setopt(curl_recv, CURLOPT_FAILONERROR, 1);
    curl_easy_setopt(curl_recv, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl_recv, CURLOPT_TCP_NODELAY, 1);
    curl_easy_setopt(curl_recv, CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(curl_recv, CURLOPT_WRITEDATA, (void *) recv_ss);
    curl_easy_setopt(curl_recv, CURLOPT_READFUNCTION, curl_read);
    curl_easy_setopt(curl_recv, CURLOPT_HEADERDATA, &Rpc::longpoll);
    curl_easy_setopt(curl_recv, CURLOPT_HEADERFUNCTION, curl_header);
    curl_easy_setopt(curl_recv, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_recv, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl_recv, CURLOPT_POST, 1);
    curl_easy_setopt(curl_recv, CURLOPT_USERPWD, userpass.c_str());
    curl_easy_setopt(curl_recv, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

    curl_easy_setopt(curl_send, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_send, CURLOPT_ENCODING, "");
    curl_easy_setopt(curl_send, CURLOPT_FAILONERROR, 1);
    curl_easy_setopt(curl_send, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl_send, CURLOPT_TCP_NODELAY, 1);
    curl_easy_setopt(curl_send, CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(curl_send, CURLOPT_WRITEDATA, (void *) recv_ss);
    curl_easy_setopt(curl_send, CURLOPT_READFUNCTION, curl_read);
    curl_easy_setopt(curl_send, CURLOPT_HEADERDATA, &Rpc::longpoll);
    curl_easy_setopt(curl_send, CURLOPT_HEADERFUNCTION, curl_header);
    curl_easy_setopt(curl_send, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_send, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl_send, CURLOPT_POST, 1);
    curl_easy_setopt(curl_send, CURLOPT_USERPWD, userpass.c_str());
    curl_easy_setopt(curl_send, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

    Rpc::server_url = url;
    Rpc::timeout    = timeout;
    curl_initialized = true;
    return true;
  }
  
  return false;
}

/* return the only instance of this */
Rpc *Rpc::get_instance() {

  log_str("get_instance", LOG_D);
  pthread_mutex_lock(&creation_mutex);
  if (!initialized) {
    only_instance = new Rpc();
    initialized   = true;
  }
  pthread_mutex_unlock(&creation_mutex);

  return (curl_initialized ? only_instance : NULL);
}

/* private constructor */
Rpc::Rpc() { }

/* destructor */
Rpc::~Rpc() { }


/**
 * Request new Work from gapcoin daemon
 * do_lp indicates whether to make a long poll request or not.
 */
BlockHeader *Rpc::getwork(bool do_lp) {

  log_str("getwork request", LOG_D);

  /* building http header */
  char content_len[64];
  struct curl_slist *header = NULL;
  static bool init_msg = false;

  sprintf(content_len, "Content-Length: %lu", getwork_rpccmd.length());
  header = curl_slist_append(header, "Content-Type: application/json");
  header = curl_slist_append(header, content_len);
  header = curl_slist_append(header, "User-Agent: " USER_AGENT);
  header = curl_slist_append(header, "Accept:"); /* disable Accept hdr*/
  header = curl_slist_append(header, "Expect:"); /* disable Expect hdr*/

  if(curl_recv) {
    if (do_lp) {
      curl_easy_setopt(curl_recv, CURLOPT_TIMEOUT, 60);
 
      /* url starts with / */
      if (longpoll.url.rfind("/") == 0)
        curl_easy_setopt(curl_recv, CURLOPT_URL, (server_url + longpoll.url).c_str());
      else
        curl_easy_setopt(curl_recv, CURLOPT_URL, longpoll.url.c_str());
        
    } else {
      curl_easy_setopt(curl_recv, CURLOPT_TIMEOUT, timeout);
      curl_easy_setopt(curl_recv, CURLOPT_URL, server_url.c_str());
    }
    curl_easy_setopt(curl_recv, CURLOPT_READDATA, (void *) &getwork_rpccmd);
    curl_easy_setopt(curl_recv, CURLOPT_HTTPHEADER, header);
  } else
    return NULL;

  CURLcode res;

  /* Perform the request, res will get the return code */ 
  res = curl_easy_perform(curl_recv);

  if (!init_msg && longpoll.supported) {
    log_str("Server supports longpoll", LOG_D);
    pthread_mutex_lock(&io_mutex);
    cout << get_time() << "Server supports longpoll" << endl; 
    pthread_mutex_unlock(&io_mutex);
    init_msg = true;
  }

  /* long poll timed out make normal getwork request */
  if (res == CURLE_OPERATION_TIMEDOUT && do_lp) {
    log_str("longpoll timeout reached", LOG_D);
    return getwork(false);
  }

  /* Check for errors */ 
  if(res != CURLE_OK)  {
    log_str(string("curl_easy_perform() failed to recv: ") + curl_easy_strerror(res), LOG_W);
    pthread_mutex_lock(&io_mutex);
    cout << get_time() << "curl_easy_perform() failed to recv: "; 
    cout << curl_easy_strerror(res) << endl;
    pthread_mutex_unlock(&io_mutex);
    return NULL;
  }


  /* parse response */
  json_t *root, *tdiff;
  json_error_t error;

  root = json_loads(recv_ss->str().c_str(), 0, &error);
  recv_ss->str("");

  if(!root) {
    log_str(string("jansson error: on line ") + itoa(error.line) + ":" + error.text, LOG_W);
    pthread_mutex_lock(&io_mutex);
    cout << get_time() << "jansson error: on line " << error.line;
    cout << ": " << error.text << endl;
    pthread_mutex_unlock(&io_mutex);
    return NULL;
  }

  if (!json_is_object(root)) {
    log_str("can not parse server response", LOG_W);
    pthread_mutex_lock(&io_mutex);
    cout << get_time() << "can not parse server response" << endl;
    pthread_mutex_unlock(&io_mutex);
    json_decref(root);
    return NULL;
  }
  root = json_object_get(root, "result");

  if (!json_is_object(root)) {
    log_str("can not parse server response", LOG_W);
    pthread_mutex_lock(&io_mutex);
    cout << get_time() << "can not parse server response" << endl;
    pthread_mutex_unlock(&io_mutex);
    json_decref(root);
    return NULL;
  }
  tdiff = json_object_get(root, "difficulty");
  if (!json_is_integer(tdiff)) {
    log_str("can not parse server difficulty", LOG_W);
    pthread_mutex_lock(&io_mutex);
    cout << get_time() << "can not parse server difficulty" << endl;
    pthread_mutex_unlock(&io_mutex);
    json_decref(tdiff);
    return NULL;
  }

  uint64_t nDiff = json_number_value(tdiff);
  json_decref(tdiff);

  root = json_object_get(root, "data");
  if (!json_is_string(root)) {
    log_str("can not parse server response", LOG_W);
    pthread_mutex_lock(&io_mutex);
    cout << get_time() << "can not parse server response" << endl;
    pthread_mutex_unlock(&io_mutex);
    json_decref(root);
    return NULL;
  }
  string data = json_string_value(root);
  json_decref(root);

  BlockHeader *head = new BlockHeader(&data);
  head->target = nDiff;
  return head;
}

/**
 * send processed work to the gapcoin daemon
 * returns true if share was accepted
 */
bool Rpc::sendwork(BlockHeader *header) {

  log_str("sendwork request", LOG_D);
  stringstream data;
  data << "{\"jsonrpc\": \"1.0\", ";
  data << "\"id\":\"" USER_AGENT "\", ";
  data << "\"method\": \"getwork\", ";
  data << "\"params\": [\"";
  data << header->get_hex();
  data << "\"] }";
  
  /* building http header */
  char content_len[64];
  struct curl_slist *httphead = NULL;
  string hex = data.str();

  sprintf(content_len, "Content-Length: %lu", hex.length());
  httphead = curl_slist_append(httphead, "Content-Type: application/json");
  httphead = curl_slist_append(httphead, content_len);
  httphead = curl_slist_append(httphead, "User-Agent: " USER_AGENT);
  httphead = curl_slist_append(httphead, "Accept:"); /* disable Accept hdr*/
  httphead = curl_slist_append(httphead, "Expect:"); /* disable Expect hdr*/

  if(curl_send) {
    curl_easy_setopt(curl_send, CURLOPT_READDATA, (void *) &hex);
    curl_easy_setopt(curl_send, CURLOPT_HTTPHEADER, httphead);
  } else
    return false;

  CURLcode res;

  /* Perform the request, res will get the return code */ 
  if (Opts::get_instance() && Opts::get_instance()->has_extra_vb()) {
    extra_verbose_log(get_time() + " rpc-payload: " + hex);
  }
  res = curl_easy_perform(curl_send);

  /* Check for errors */ 
  if(res != CURLE_OK) {
    log_str(string("curl_easy_perform() failed to send: ") + curl_easy_strerror(res), LOG_W);
    pthread_mutex_lock(&io_mutex);
    cout << get_time() << "curl_easy_perform() failed to send: ";
    cout << curl_easy_strerror(res) << endl;
    pthread_mutex_unlock(&io_mutex);
    return false;
  }


  /* parse the response */
  json_t *root;
  json_error_t error;

  std::string response = recv_ss->str();
  if (Opts::get_instance() && Opts::get_instance()->has_extra_vb()) {
    extra_verbose_log(get_time() + " rpc-response: " + response);
  }
  root = json_loads(response.c_str(), 0, &error);
  recv_ss->str("");

  if(!root) {
    log_str(string("jansson error: on line ") + itoa(error.line) + ":" + error.text, LOG_W);
    pthread_mutex_lock(&io_mutex);
    cout << get_time() << "jansson error: on line " << error.line;
    cout << ": " << error.text << endl;
    pthread_mutex_unlock(&io_mutex);
    return false;
  }

  if (!json_is_object(root)) {
    log_str("can not parse server response", LOG_W);
    pthread_mutex_lock(&io_mutex);
    cout << get_time() << "can not parse server response" << endl;
    pthread_mutex_unlock(&io_mutex);
    json_decref(root);
    return false;
  }
  root = json_object_get(root, "result");

  if (!json_is_boolean(root)) {
    log_str("can not parse server response", LOG_W);
    pthread_mutex_lock(&io_mutex);
    cout << get_time() << "can not parse server response" << endl;
    pthread_mutex_unlock(&io_mutex);
    json_decref(root);
    return false;
  }
  bool result = json_is_true(root);
  json_decref(root);

  return result;
}
