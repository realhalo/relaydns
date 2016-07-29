/* [relaydns] db.c :: configuration and overall database handling.
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

#include "relaydns.h"

extern struct RELAYDNS_DB_CONF_S relaydns_db_conf;
extern struct RELAYDNS_DB_INFO_S relaydns_db_info;
extern struct RELAYDNS_FLOOD_PROT_S relaydns_flood_prot;

redisContext *redis_context = NULL;

// get data from redis to set relaydns_db_info's general info. (ns ips, www ip, and other static info)
char relaydns_db_info_setup() {
	int i, j;
	unsigned char buf[RELAYDNS_IP6_LEN]; // ip6 > ip4, so just use that for either.
	struct sockaddr_in addr;
	redisReply *rr;

#ifdef RELAYDNS_DEBUG
	printf("relaydns_db_info_setup()\n");
#endif

	// clear out the existing hard ip data.
	memset(&relaydns_db_info, 0, sizeof(relaydns_db_info));

	// default this to the default. (> 0, just incase we have an early exit)
	relaydns_db_info.key_exp = RELAYDNS_REDIS_KEY_EXP;

	rr = redisCommand(redis_context, "SELECT %u", relaydns_db_conf.db_conf);
	freeReplyObject(rr);

	// query the db for our nameservers. (ipv4)
	rr = redisCommand(redis_context, "LRANGE conf:ns 0 -1");
	if (rr && rr->type == REDIS_REPLY_ARRAY) {
		for(i=rr->elements-1; i >= 0 && relaydns_db_info.ns_total < RELAYDNS_MAX_NS_IPS; i--) {
			if(inet_pton(AF_INET, rr->element[i]->str, buf) > 0)
				memcpy(&relaydns_db_info.ns_ip[relaydns_db_info.ns_total++], buf, RELAYDNS_IP_LEN);
		}
	}
	freeReplyObject(rr);

	// we need at least one name server for this getup to work.
	if(relaydns_db_info.ns_total == 0) {
		rr = redisCommand(redis_context, "SELECT %u", relaydns_db_conf.db_data);
		freeReplyObject(rr);
		return(RELAYDNS_FALSE);
	}

	// query the db for our nameservers. (ipv6, we only need as many as we have ipv4)
	relaydns_db_info.ns_ip6_disabled = RELAYDNS_FALSE;
	rr = redisCommand(redis_context, "LRANGE conf:ns6 0 -1");
	if (rr && rr->type == REDIS_REPLY_ARRAY) {
		j = 0;
		for(j=0; j < relaydns_db_info.ns_total; ) {
			for(i=rr->elements-1; i >= 0 && relaydns_db_info.ns_total > j; i--) {
				if(inet_pton(AF_INET6, rr->element[i]->str, buf) > 0)
					memcpy(&relaydns_db_info.ns_ip6[j++], buf, RELAYDNS_IP6_LEN);
				else
					memset(&relaydns_db_info.ns_ip6[j++], 0, RELAYDNS_IP6_LEN);

			}
			// must not be any ipv6 records, disable it.
			if(j == 0) {
				relaydns_db_info.ns_ip6_disabled = RELAYDNS_TRUE;
				break;
			}
		}
	}
	freeReplyObject(rr);

	// get root ip. (ipv4, if not set, defaults to 0.0.0.0)
	rr = redisCommand(redis_context, "GET conf:root_ip");
	if(rr && rr->str && inet_aton(rr->str, &addr.sin_addr) > 0)
		relaydns_db_info.root_ip = (unsigned int)addr.sin_addr.s_addr;
	freeReplyObject(rr);

	// get root ip. (ipv6, if not set, defaults to "::")
	rr = redisCommand(redis_context, "GET conf:root_ip6");
	if(rr && rr->str && inet_pton(AF_INET6, rr->str, buf) > 0)
		memcpy(&relaydns_db_info.root_ip6, buf, RELAYDNS_IP6_LEN);
	freeReplyObject(rr);

	// get root txt. (if not set, defaults to nothing)
	rr = redisCommand(redis_context, "GET conf:root_txt");
	if(rr && rr->str)
		memcpy(&relaydns_db_info.root_txt, rr->str, strlen(rr->str) > RELAYDNS_TXT_LEN ? RELAYDNS_TXT_LEN : strlen(rr->str));
	freeReplyObject(rr);

	// get key expiration time. (if not set, default was set in the beginning of this function to RELAYDNS_REDIS_KEY_EXP)
	rr = redisCommand(redis_context, "GET conf:key_exp");
	if(rr && rr->str)
		relaydns_db_info.key_exp = (unsigned short)atoi(rr->str);
	if(relaydns_db_info.key_exp == 0)
		relaydns_db_info.key_exp = RELAYDNS_REDIS_KEY_EXP;
	freeReplyObject(rr);

	rr = redisCommand(redis_context, "SELECT %u", relaydns_db_conf.db_data);
	freeReplyObject(rr);

	return(RELAYDNS_TRUE);
}

// attempt to connect to the redis server, and select the "data" db.
char relaydns_db_connect(char run_setup) {
	struct timeval to = { relaydns_db_conf.timeout, 0 };
	redisReply *rr;

#ifdef RELAYDNS_DEBUG
	printf("relaydns_db_connect(%d): %s:%d timeout=%d password='%s'\n", run_setup, relaydns_db_conf.host, relaydns_db_conf.port, relaydns_db_conf.timeout, relaydns_db_conf.pass);
#endif

	if (!(redis_context=redisConnectWithTimeout(relaydns_db_conf.host, relaydns_db_conf.port, to)) || redis_context->err) {
#ifdef RELAYDNS_DEBUG
		if (redis_context)
			printf("Connection error: %s\n", redis_context->errstr);
		else
			printf("Connection error: can't allocate redis context\n");
#endif

		// a little delay incase of retries.
		usleep(relaydns_db_conf.retry_usleep);
		return(RELAYDNS_FALSE);
	}
	else if(strlen(relaydns_db_conf.pass) > 0) {
		rr = redisCommand(redis_context, "AUTH %s", relaydns_db_conf.pass);
		if(rr->type != REDIS_REPLY_STATUS) {
#ifdef RELAYDNS_DEBUG
			printf("Redis AUTH failed!\n");
#endif
			freeReplyObject(rr);
			return(RELAYDNS_FALSE);
		}
		freeReplyObject(rr);
	}

	if(run_setup && relaydns_db_info_setup() != RELAYDNS_TRUE) {
#ifdef RELAYDNS_DEBUG
		printf("relaydns_db_info_setup() FAILED!\n");
#endif
		return(RELAYDNS_FALSE);
	}

	rr = redisCommand(redis_context, "SELECT %u", relaydns_db_conf.db_data);
	freeReplyObject(rr);

	return(RELAYDNS_TRUE);
}

// push a (string) value to redis. (goes into the "data" dn)
char relaydns_db_set(unsigned char *name, unsigned char *value, unsigned int value_len) {
	char ret = RELAYDNS_FALSE;
	int i = relaydns_db_conf.retry;
	redisReply *rr;

	// flood protection limit hit?
	if(relaydns_flood_prot.set_max && relaydns_flood_prot.set >= relaydns_flood_prot.set_max)
		return(ret);

	do {
		if(value_len > 0)
			rr = redisCommand(redis_context, "SETNX %s %b", name, value, value_len);
		else
			rr = redisCommand(redis_context, "SETNX %s %s", name, value);

		if(redis_context->err)
			relaydns_db_connect(RELAYDNS_TRUE);
		else {
			if(rr->type == REDIS_REPLY_INTEGER && rr->integer == 1) {
				freeReplyObject(rr);
				ret = RELAYDNS_TRUE;

				relaydns_flood_prot.set++; // +1 for flood protection checks.

				// POTENTIAL ISSUE: this could fail and leave infinite keys roaming around.
				if(relaydns_db_info.key_exp > 0) {
#ifdef RELAYDNS_DEBUG
printf("EXPIRE %s %u\n", name, relaydns_db_info.key_exp);
#endif
					rr = redisCommand(redis_context, "EXPIRE %s %u", name, relaydns_db_info.key_exp);
					if(!redis_context->err)
						freeReplyObject(rr);
				}

			}
			else
				freeReplyObject(rr);
			break;
		}
	} while(--i > 0);
/*
// REMOVE THIS, JUST STRESS TESTING
        for(i=0; i< 100; i++) {
                rr = redisCommand(redis_context, "SETNX %s%i %s", name, i, value);
                freeReplyObject(rr);
		if(relaydns_db_info.key_exp > 0) {
			rr = redisCommand(redis_context, "EXPIRE %s%i %u", name, i, relaydns_db_info.key_exp);
			freeReplyObject(rr);
		}
        }
// REMOVE THIS, JUST STRESS TESTING
*/
	return(ret);
}

// pull a (string) value from redis. (pulls from "data" db, THIS NEEDS TO BE FREE'D BY THE CALLER!)
unsigned char *relaydns_db_get(unsigned char *name, unsigned int verify_len) {
	unsigned char *ret=NULL;
	int i = relaydns_db_conf.retry;
	redisReply *rr;

	// flood protection limit hit?
	if(relaydns_flood_prot.get_max && relaydns_flood_prot.get >= relaydns_flood_prot.get_max)
		return(ret);

	relaydns_flood_prot.get++; // +1 for flood protection checks.

	do {
		rr = redisCommand(redis_context, "GET %s", name);
		if(redis_context->err)
			relaydns_db_connect(RELAYDNS_TRUE);
		else {
			if(rr && rr->str && rr->len > 0 && (verify_len == 0 || verify_len == rr->len)) {
				if((ret=(unsigned char *)malloc(rr->len+1))) {
					memcpy(ret, rr->str, rr->len);
					ret[rr->len] = 0;
				}
			}
			freeReplyObject(rr);
			break;
		}
	} while(--i > 0);

	return(ret);
}

// run arbitrary redis command. (used for quick debugging/testing)
void relaydns_db_command(char *cmd) {
	redisReply *rr;
	rr = redisCommand(redis_context, cmd);
	printf("DB CMD: %s\n", cmd);
	printf("DB RESP: %s\n", rr->str);
	freeReplyObject(rr);
	return;
}

// reset relaydns_db_conf's conf settings to defaults.
void relaydns_db_conf_set_defaults() {
	strncpy(relaydns_db_conf.host, RELAYDNS_REDIS_HOST, RELAYDNS_STRSIZE-1);
	relaydns_db_conf.port = RELAYDNS_REDIS_PORT;
	strncpy(relaydns_db_conf.pass, RELAYDNS_REDIS_PASS, RELAYDNS_STRSIZE-1);
	relaydns_db_conf.timeout = RELAYDNS_REDIS_TIMEOUT;
	relaydns_db_conf.retry = RELAYDNS_REDIS_RETRY;
	relaydns_db_conf.retry_usleep = RELAYDNS_REDIS_RETRY_USLEEP;
	relaydns_db_conf.db_conf = RELAYDNS_REDIS_DB_CONF;
	relaydns_db_conf.db_data = RELAYDNS_REDIS_DB_DATA;
	relaydns_db_conf.reload_exp = RELAYDNS_REDIS_RELOAD_EXP;
	return;
}
