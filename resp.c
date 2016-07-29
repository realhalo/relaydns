/* [relaydns] resp.c :: initial packet setup for dns responses.
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

extern struct RELAYDNS_DB_INFO_S relaydns_db_info;
extern struct RELAYDNS_BINARYBUF_S wbuf;

// respond with no answers, just an RCODE.
void relaydns_resp_none(unsigned char rcode) {
	unsigned char *wptr=wbuf.data;
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;
	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;
	wdns->rcode = rcode;
	wbuf.len = wptr - wbuf.data;
	return;
}

// response for SOA question.
void relaydns_resp_soa(unsigned short root_offset) {
	unsigned char *wptr=wbuf.data;
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;

	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;

	// add om SOA record.
	wdns->a_count = htons(1);
	wptr += relaydns_add_soa(root_offset, &wptr);

	// add in auth NS records.
	wdns->auth_count = htons(relaydns_db_info.ns_total);
	wptr += relaydns_add_ns(root_offset, &wptr);

	wbuf.len = wptr - wbuf.data;
	return;
}

// response for CNAME question. (sub-domain, assume to pull a key)
void relaydns_resp_cname_key_get(unsigned short root_offset, unsigned short offset, unsigned char *label) {
	unsigned char *wptr=wbuf.data, *valbuf=(unsigned char *)relaydns_db_get(label, 0);
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;
	if(!valbuf)
		return;
	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;
	wdns->a_count = htons(1);
	wptr += relaydns_add_name(RELAYDNS_TYPE_CNAME, 0, offset, valbuf, offset, &wptr);
	wbuf.len = wptr - wbuf.data;
	free(valbuf); // we're responsible for freeing this.
	return;
}

// response for CNAME question. (double-sub-domain, assume to push a key with a value)
void relaydns_resp_cname_key_set(unsigned short sub_offset, unsigned short offset, unsigned char *key, unsigned char *value) {
	unsigned char *wptr=wbuf.data;
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;

	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;
	wdns->a_count = htons(2);
	wptr += relaydns_add_name(RELAYDNS_TYPE_CNAME, 0, offset, 0, sub_offset, &wptr);
	if(relaydns_db_set(key, value, 0) == RELAYDNS_TRUE)
		wptr += relaydns_add_a(offset, 0, &wptr);
	else
		wptr += relaydns_add_a(offset, -1, &wptr);
	wbuf.len = wptr - wbuf.data;
	return;
}

// response for NS question. (send back data stored on redis server about our NS ips)
void relaydns_resp_ns(unsigned short root_offset) {
	unsigned char *wptr=wbuf.data;
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;

	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;
	wdns->a_count = htons(relaydns_db_info.ns_total);
	wptr += relaydns_add_ns(root_offset, &wptr);

	// add om SOA record.
	wdns->auth_count = htons(1);
	wptr += relaydns_add_soa(root_offset, &wptr);

	wbuf.len = wptr - wbuf.data;
	return;
}

// response for A question. (send back data stored on redis server about our root A ip)
void relaydns_resp_a_root(unsigned short root_offset) {
	unsigned char *wptr=wbuf.data;
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;

	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;

	wdns->a_count = htons(1);

	// add A record.
	wptr += relaydns_add_a(root_offset, relaydns_db_info.root_ip, &wptr);

	// add in auth NS records.
	wdns->auth_count = htons(relaydns_db_info.ns_total);
	wptr += relaydns_add_ns(root_offset, &wptr);

	// set final length for the write packet. (this being set to non-zero is what indicates we have something to send out)
	wbuf.len = wptr - wbuf.data;
	return;
}

// response for A question. (sub-domain request, multiple potential routes)
void relaydns_resp_a_sub(unsigned short root_offset, unsigned short offset, unsigned char *label) {
	unsigned int labellen=strlen((char *)label), nslen=strlen(RELAYDNS_NS_PREFIX), n=0;
	unsigned char *wptr=wbuf.data, *valbuf, ip_key[strlen((char *)label)+4];
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;

	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;

	// see if it's a name server record.
	if(labellen == nslen+1 && !strncasecmp((char *)label, RELAYDNS_NS_PREFIX, nslen) && isdigit(label[nslen])) {
		n = label[nslen] - 0x30;
		if(n >= relaydns_db_info.ns_total)
			return;

		// add A record.
		wdns->a_count = htons(1);
		wptr += relaydns_add_a(offset, relaydns_db_info.ns_ip[n], &wptr);

		// add in auth NS records.
		wdns->auth_count = htons(relaydns_db_info.ns_total);
		wptr += relaydns_add_ns(root_offset, &wptr);

	}

	// see if it's a reserved domain.
	else if(!strcasecmp((char *)label, RELAYDNS_WWW_SUBDOMAIN)) {
		wdns->a_count = htons(2);
		wptr += relaydns_add_name(RELAYDNS_TYPE_CNAME, 0, offset, 0, root_offset, &wptr);
		wptr += relaydns_add_a(root_offset, relaydns_db_info.root_ip, &wptr);
	}

	// see if it's server time request. (used to synchronize clients)
	else if(!strcasecmp((char *)label, RELAYDNS_TIME_SUBDOMAIN)) {
		wdns->a_count = htons(1);
		wptr += relaydns_add_a(root_offset, time(NULL), &wptr);
	}

	// see if it's a PTR record we need to report back.
	else {
		sprintf((char *)ip_key, "ip:%s", label);
		if((valbuf=relaydns_db_get(ip_key, RELAYDNS_IP6_LEN))) {
			if((n=relaydns_misc_ip6addr_to_ip4addr(valbuf)) > 0) {
				wdns->a_count = htons(1);
				wptr += relaydns_add_a(offset, htonl(n), &wptr);
			}
			free(valbuf);
		}
	}
	wbuf.len = wptr - wbuf.data;
	return;
}

// response for A question. (double-sub-domain, assume to push a key with a value)
void relaydns_resp_a_key_set(unsigned short sub_offset, unsigned short offset, unsigned char *key, unsigned char *value) {
	unsigned char *wptr=wbuf.data;
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;
	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;
	wdns->a_count = htons(1);
	// just a time request (allow the arbitrary 2nd part of the domain to be used to be random for the client)
	if(!strcasecmp((char *)key, RELAYDNS_TIME_SUBDOMAIN))
		wptr += relaydns_add_a(offset, time(NULL), &wptr);
	// an actual key set request
	else if(relaydns_db_set(key, value, 0) == RELAYDNS_TRUE)
		wptr += relaydns_add_a(offset, 0, &wptr); // 0.0.0.0
	else
		wptr += relaydns_add_a(offset, -1, &wptr); // 255.255.255.255
	wbuf.len = wptr - wbuf.data;
	return;
}

// response for ANY question. (root-domain, send back various info from our redis server)
void relaydns_resp_any_root(unsigned short root_offset) {
	unsigned char *wptr=wbuf.data;
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;
	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;
	wptr += relaydns_add_a(root_offset, relaydns_db_info.root_ip, &wptr);
	wptr += relaydns_add_soa(root_offset, &wptr);
	wptr += relaydns_add_ns(root_offset, &wptr);
	wdns->a_count = htons(relaydns_db_info.ns_total + 1 + 1);
	wbuf.len = wptr - wbuf.data;
	return;
}

// response for ANY question. (just passing to A logic for now)
void relaydns_resp_any_sub(unsigned short root_offset, unsigned short offset, unsigned char *label) {
	relaydns_resp_a_sub(root_offset, offset, label);
	return;
}
// response for ANY question. (just passing to A logic for now)
void relaydns_resp_any_key_set(unsigned short sub_offset, unsigned short offset, unsigned char *key, unsigned char *value) {
	relaydns_resp_a_key_set(sub_offset, offset, key, value);
	return;
}

// response for A question. (send back data stored on redis server about our root AAAA ip)
void relaydns_resp_aaaa_root(unsigned short root_offset) {
	unsigned char *wptr=wbuf.data;
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;
	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;
	wdns->a_count = htons(1);
	wptr += relaydns_add_aaaa(root_offset, relaydns_db_info.root_ip6, &wptr, RELAYDNS_FALSE);
	wbuf.len = wptr - wbuf.data;
	return;
}

// response for AAAA question. (sub-domain request, multiple potential routes)
void relaydns_resp_aaaa_sub(unsigned short root_offset, unsigned short offset, unsigned char *label) {
	unsigned int labellen=strlen((char *)label), nslen=strlen(RELAYDNS_NS_PREFIX), n=0;
	unsigned char *wptr=wbuf.data, *valbuf, ip_key[strlen((char *)label)+4];
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;

	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;

	// see if it's a name server record.
	if(labellen == nslen+1 && !strncasecmp((char *)label, RELAYDNS_NS_PREFIX, nslen) && isdigit(label[nslen])) {
		n = label[nslen] - 0x30;
		if(relaydns_db_info.ns_ip6_disabled || n >= relaydns_db_info.ns_total)
			return;

		// add AAAA record.
		wdns->a_count = htons(1);
		wptr += relaydns_add_aaaa(offset, relaydns_db_info.ns_ip6[n], &wptr, RELAYDNS_FALSE);

		// add in auth NS records.
		wdns->auth_count = htons(relaydns_db_info.ns_total);
		wptr += relaydns_add_ns(root_offset, &wptr);
	}

	// see if it's a reserved domain.
	else if(!strcasecmp((char *)label, RELAYDNS_WWW_SUBDOMAIN)) {
		wdns->a_count = htons(2);
		wptr += relaydns_add_name(RELAYDNS_TYPE_CNAME, 0, offset, 0, root_offset, &wptr);
		wptr += relaydns_add_aaaa(root_offset, relaydns_db_info.root_ip6, &wptr, RELAYDNS_FALSE);
	}

	// see if it's a PTR record we need to report back.
	else {
		sprintf((char *)ip_key, "ip:%s", label);
		if((valbuf=relaydns_db_get(ip_key, RELAYDNS_IP6_LEN))) {
			wdns->a_count = htons(1);
			wptr += relaydns_add_aaaa(offset, valbuf, &wptr, RELAYDNS_FALSE);
			free(valbuf);
		}
	}
	wbuf.len = wptr - wbuf.data;
	return;
}

// response for AAAA question. (double-sub-domain, assume to push a key with a value)
void relaydns_resp_aaaa_key_set(unsigned short sub_offset, unsigned short offset, unsigned char *key, unsigned char *value) {
	unsigned char *wptr=wbuf.data, ipbuf[RELAYDNS_IP6_LEN];
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;
	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;
	wdns->a_count = htons(1);
	if(relaydns_db_set(key, value, 0) == RELAYDNS_TRUE)
		memset(ipbuf, 0, RELAYDNS_IP6_LEN);
	else
		memset(ipbuf, 0xFF, RELAYDNS_IP6_LEN);
	wptr += relaydns_add_aaaa(offset, ipbuf, &wptr, RELAYDNS_FALSE);
	wbuf.len = wptr - wbuf.data;
	return;
}

// response for TXT question. (root-domain, send data from our redis server)
void relaydns_resp_txt_root(unsigned short root_offset) {
	unsigned char *wptr=wbuf.data;
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;
	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;
	if(relaydns_db_info.root_txt && *relaydns_db_info.root_txt) {
		wptr += relaydns_add_txt(relaydns_db_info.root_txt, root_offset, &wptr);
		wdns->a_count = htons(1);
		wbuf.len = wptr - wbuf.data;
	}
	return;
}

// response for TXT question. (sub-domain, assume to pull a key)
void relaydns_resp_txt_key_get(unsigned short root_offset, unsigned short offset, unsigned char *label) {
	unsigned char *wptr=wbuf.data, *valbuf=(unsigned char *)relaydns_db_get(label, 0);
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;
	if(!valbuf)
		return;
	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;
	wdns->a_count = htons(1);
	wptr += relaydns_add_txt(valbuf, offset, &wptr);
	wbuf.len = wptr - wbuf.data;
	free(valbuf);
}

// response for PTR question. (sub-domain, assume to set a key as the requester's ip, returns "true" if set, "false" if the key is taken)
void relaydns_resp_ptr_key_set(unsigned short root_offset, unsigned short offset, unsigned char *key, struct in6_addr ip_addr) {
	unsigned char *wptr=wbuf.data, ip_key[strlen((char *)key)+4];
	struct RELAYDNS_HEADER_S *wdns = (struct RELAYDNS_HEADER_S *)wbuf.data;
	wptr += relaydns_add_boilerplate();
	wdns->qr = wdns->aa = wdns->rd = RELAYDNS_TRUE;
	wdns->a_count = htons(1);
	sprintf((char *)ip_key, "ip:%s", key);
	if(relaydns_db_set(ip_key, (unsigned char *)ip_addr.s6_addr, RELAYDNS_IP6_LEN) == RELAYDNS_TRUE)
		wptr += relaydns_add_name(RELAYDNS_TYPE_PTR, 0, offset, (unsigned char *)"true", root_offset, &wptr);
	else
		wptr += relaydns_add_name(RELAYDNS_TYPE_PTR, 0, offset, (unsigned char *)"false", root_offset, &wptr);
	wbuf.len = wptr - wbuf.data;
	return;
}
