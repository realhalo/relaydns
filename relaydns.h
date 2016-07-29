/* [relaydns] relaydns.h :: all purpose include for the lazy man.
** Copyright (C) 2016 fakehalo [v9@fakehalo.us]
**
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include <hiredis.h>

#define RELAYDNS_VERSION "1.0"

#define RELAYDNS_DEFAULT_UID 65534
#define RELAYDNS_DEFAULT_GID 65534

#define RELAYDNS_STRSIZE 256
#define RELAYDNS_BUFSIZE 1024
#define RELAYDNS_TRUE 1
#define RELAYDNS_FALSE 0
#define RELAYDNS_HEADER_SIZE 12
#define RELAYDNS_PORT 53
#define RELAYDNS_MAX_DOMAIN_SIZE 255
#define RELAYDNS_MAX_LABEL_SIZE 63
#define RELAYDNS_MAX_LABELS 4
#define RELAYDNS_MAX_NS_IPS 10 // support needs to be added if >10. (single numeric used currently)

#define RELAYDNS_WWW_SUBDOMAIN "www"
#define RELAYDNS_TIME_SUBDOMAIN "time"

#define RELAYDNS_IP_LEN 4
#define RELAYDNS_IP6_LEN 16
#define RELAYDNS_TXT_LEN 255

#define RELAYDNS_MISC_TTL 900
#define RELAYDNS_SOA_TTL 900
#define RELAYDNS_SOA_REFRESH_TTL 3600
#define RELAYDNS_SOA_RETRY_TTL 3600
#define RELAYDNS_SOA_EXPIRE_TTL 1209600
#define RELAYDNS_SOA_MINIMUM_TTL 3600
#define RELAYDNS_SOA_SERIAL 2016010100

#define RELAYDNS_CLASS_IN 1

#define RELAYDNS_TYPE_NS 2
#define RELAYDNS_TYPE_MX 15
#define RELAYDNS_TYPE_PTR 12
#define RELAYDNS_TYPE_SOA 6
#define RELAYDNS_TYPE_A 1
#define RELAYDNS_TYPE_AAAA 28
#define RELAYDNS_TYPE_CNAME 5
#define RELAYDNS_TYPE_TXT 16
#define RELAYDNS_TYPE_ANY 255

#define RELAYDNS_OPCODE_STANDARD 0
#define RELAYDNS_OPCODE_INVERSE 1
#define RELAYDNS_OPCODE_STATUS 2

#define RELAYDNS_RCODE_NOERROR 0
#define RELAYDNS_RCODE_FMTERROR 1
#define RELAYDNS_RCODE_SERVFAIL 2
#define RELAYDNS_RCODE_NXDOMAIN 3
#define RELAYDNS_RCODE_NOTIMPLEMENTED 4
#define RELAYDNS_RCODE_REFUSED 5

#define RELAYDNS_REDIS_HOST "127.0.0.1"
#define RELAYDNS_REDIS_PORT 6379
#define RELAYDNS_REDIS_PASS ""
#define RELAYDNS_REDIS_TIMEOUT 30
#define RELAYDNS_REDIS_RETRY 2
#define RELAYDNS_REDIS_RETRY_USLEEP 1000000
#define RELAYDNS_REDIS_DB_CONF 1
#define RELAYDNS_REDIS_DB_DATA 0
#define RELAYDNS_REDIS_KEY_EXP 595	// 10 mintues. (- 5 seconds to make recreation easier on the minute)
#define RELAYDNS_REDIS_RELOAD_EXP 3600	// 1 hour. (reload distributed config from db)

#define RELAYDNS_NS_PREFIX "ns"

// normal character array with length included to allow for null-bytes.
struct RELAYDNS_BINARYBUF_S {
	unsigned char data[RELAYDNS_BUFSIZE];
	unsigned int len;
};

// information (from commandline) to connect to redis database.
struct RELAYDNS_DB_CONF_S {
	char host[RELAYDNS_STRSIZE];
	char pass[RELAYDNS_STRSIZE];
	unsigned short port;		// redis port
	unsigned int timeout;		// redis connection timeout (passed directly to redis api)
	unsigned char retry;		// number or retries on db connection failure
	useconds_t retry_usleep;	// delay between retries on db connection failure
	unsigned char db_conf;		// redis "conf" database number (default = RELAYDNS_REDIS_DB_CONF)
	unsigned char db_data;		// redis "data" database number (default = RELAYDNS_REDIS_DB_DATA)
	unsigned int reload_exp;	// reload config "info" after X seconds.
};

// information (distributed from redis) to use with this relaydns instance.
struct RELAYDNS_DB_INFO_S {
	unsigned int ns_ip[RELAYDNS_MAX_NS_IPS];
	unsigned char ns_ip6[RELAYDNS_MAX_NS_IPS][RELAYDNS_IP6_LEN];
	char ns_ip6_disabled;
	unsigned int ns_total;
	unsigned int root_ip;
	unsigned char root_ip6[RELAYDNS_IP6_LEN];
	unsigned char root_txt[RELAYDNS_TXT_LEN];
	unsigned short key_exp;
};

// general flood protection. (0 = unlimited)
struct RELAYDNS_FLOOD_PROT_S {
	unsigned int in;
	unsigned int in_max;
	unsigned int out;
	unsigned int out_max;
	unsigned int get;
	unsigned int get_max;
	unsigned int set;
	unsigned int set_max;
};

// all purpose dns header masked against character arrays
struct RELAYDNS_HEADER_S {
	unsigned short id;		// identification number

	unsigned char rd :1;		// recursion desired
	unsigned char tc :1;		// truncated message
	unsigned char aa :1;		// authoritive answer
	unsigned char opcode :4;	// purpose of message
	unsigned char qr :1;		// query/response flag

	unsigned char rcode :4;		// response code
	unsigned char cd :1;		// checking disabled
	unsigned char ad :1;		// authenticated data
	unsigned char z :1;		// its z! reserved
	unsigned char ra :1;		// recursion available

	unsigned short q_count;		// number of question entries
	unsigned short a_count;		// number of answer entries
	unsigned short auth_count;	// number of authority entries
	unsigned short add_count;	// number of resource entries
};

// used to calculate dns compression offsets. (ie. 0xc00c)
#define RELAYDNS_OFFSET_TO_SHORT(x) ((((x) & 0x3FFF) | 0xc000) + sizeof(struct RELAYDNS_HEADER_S))

// add.c
unsigned int relaydns_add_name2wbuf(unsigned char *, unsigned char **);
unsigned int relaydns_add_boilerplate();
unsigned int relaydns_add_name(unsigned short, unsigned char *, unsigned short, unsigned char *, unsigned short, unsigned char **);
unsigned int relaydns_add_soa(unsigned short, unsigned char **);
unsigned int relaydns_add_ns(unsigned short, unsigned char **);
unsigned int relaydns_add_a(unsigned short, unsigned int ip, unsigned char **);
unsigned int relaydns_add_aaaa(unsigned short, unsigned char *, unsigned char **, char);
unsigned int relaydns_add_txt(unsigned char *, unsigned short, unsigned char **);

// resp.c
void relaydns_resp_none(unsigned char);
void relaydns_resp_soa(unsigned short);
void relaydns_resp_cname_key_get(unsigned short, unsigned short, unsigned char *);
void relaydns_resp_cname_key_set(unsigned short, unsigned short, unsigned char *, unsigned char *);
void relaydns_resp_ns(unsigned short);
void relaydns_resp_a_root(unsigned short);
void relaydns_resp_a_sub(unsigned short, unsigned short, unsigned char *);
void relaydns_resp_a_key_set(unsigned short, unsigned short, unsigned char *, unsigned char *);
void relaydns_resp_any_root(unsigned short);
void relaydns_resp_any_sub(unsigned short, unsigned short, unsigned char *);
void relaydns_resp_any_key_set(unsigned short, unsigned short, unsigned char *, unsigned char *);
void relaydns_resp_aaaa_root(unsigned short);
void relaydns_resp_aaaa_sub(unsigned short, unsigned short, unsigned char *);
void relaydns_resp_aaaa_key_set(unsigned short, unsigned short, unsigned char *, unsigned char *);
void relaydns_resp_txt_root(unsigned short);
void relaydns_resp_txt_key_get(unsigned short, unsigned short, unsigned char *);
void relaydns_resp_ptr_key_set(unsigned short, unsigned short, unsigned char *, struct in6_addr);

// parse.c
void relaydns_parse_loop(int, unsigned int);
char relaydns_parse_packet(unsigned char *, unsigned int, struct in6_addr);
char relaydns_parse_query(unsigned char *buf, unsigned int len, struct in6_addr);

// db.c
char relaydns_db_info_setup();
char relaydns_db_connect(char);
char relaydns_db_set(unsigned char *, unsigned char *, unsigned int);
unsigned char *relaydns_db_get(unsigned char *, unsigned int);
void relaydns_db_conf_set_defaults();
void relaydns_db_command(char *);

// misc.c
unsigned int relaydns_misc_ip6addr_to_ip4addr(unsigned char *);
void relaydns_misc_signal_setup();
void relaydns_misc_signal(int);
char relaydns_set_perm(uid_t, gid_t);
void relaydns_misc_print_usage(char *);
