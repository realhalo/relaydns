/* [relaydns] parse.c :: controller for incoming dns packets.
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

extern struct RELAYDNS_BINARYBUF_S rbuf, wbuf;
extern struct RELAYDNS_FLOOD_PROT_S relaydns_flood_prot;

// main loop for the dns server.
void relaydns_parse_loop(int fd, unsigned int reload_exp) {
	struct sockaddr_in6 caddr;
	socklen_t clen = sizeof(struct sockaddr_in6);
	time_t this_second=NULL, next_conf_reload_second=time(NULL) + reload_exp;
#ifdef RELAYDNS_DEBUG
	char ipstr[INET6_ADDRSTRLEN];
	unsigned int i;
#endif

	while(RELAYDNS_TRUE) {
#ifdef RELAYDNS_DEBUG
		printf("------------ START CYCLE -----------\n");
#endif
		// reset flood protection on each second.
		if(this_second != time(NULL)) {
			relaydns_flood_prot.get = 0;
			relaydns_flood_prot.set = 0;
			relaydns_flood_prot.in = 0;
			relaydns_flood_prot.out = 0;
			this_second = time(NULL);

			// see if we need to reload the configuration.
			if(this_second > next_conf_reload_second && reload_exp > 0) {
#ifdef RELAYDNS_DEBUG
				printf("RELOAD CONF: %u > %u\n", (unsigned int)this_second, (unsigned int)next_conf_reload_second);
#endif
				relaydns_db_info_setup();
				next_conf_reload_second = this_second + reload_exp;
			}
		}

		memset(&rbuf, 0, sizeof(struct RELAYDNS_BINARYBUF_S));

		// get our dns request.
		rbuf.len = recvfrom(fd, rbuf.data, RELAYDNS_BUFSIZE, 0, (struct sockaddr *)&caddr, &clen);

#ifdef RELAYDNS_DEBUG
		printf("RECV: %d bytes (pre-parsing from IP: %s)\n", rbuf.len, inet_ntop(AF_INET6, &caddr.sin6_addr, ipstr, INET6_ADDRSTRLEN));
#endif

		if (rbuf.len <= RELAYDNS_HEADER_SIZE)
			continue;

		// FLOODPROT: stop processing any further if we've hit our max.
		if(relaydns_flood_prot.in_max && relaydns_flood_prot.in >= relaydns_flood_prot.in_max)
			continue;
		// FLOODPROT: might as well stop it before it processes any further if we can't write back.
		else if(relaydns_flood_prot.out_max && relaydns_flood_prot.out >= relaydns_flood_prot.out_max)
			continue;

		relaydns_flood_prot.in++;

		// parse the packet and verify it's "normal".
		if(relaydns_parse_packet(rbuf.data, rbuf.len, caddr.sin6_addr) != RELAYDNS_TRUE)
			continue;

		// nothing was done? send back a NOERROR response.
		if(wbuf.len == 0)
			relaydns_resp_none(RELAYDNS_RCODE_NOERROR);

		// should always be true because of the above, but just to be safe...
		if(wbuf.len > 0) {
			relaydns_flood_prot.out++;

#ifdef RELAYDNS_DEBUG
			printf("SEND: ");
			for(i=0; i < wbuf.len; i++) {
				printf("%02x ", wbuf.data[i]);
			}
			printf("\n");
#endif

			// sendto: echo the input back to the client. (doesn't matter if it fails)
			(void)sendto(fd, wbuf.data, wbuf.len, 0, (struct sockaddr *)&caddr, clen);

			// clear out the write buffer for the next run.
			memset(&wbuf, 0, sizeof(struct RELAYDNS_BINARYBUF_S));
		}
#ifdef RELAYDNS_DEBUG
		printf("------------ END CYCLE -----------\n");
#endif
	}
	return;
}

// parse the basics of the packet, make sure it meets the basic criteria to parse further.
char relaydns_parse_packet(unsigned char *buf, unsigned int len, struct in6_addr ip_addr) {
	unsigned short qs;
#ifdef RELAYDNS_DEBUG
	unsigned short an, au, ad;
	unsigned int i;
#endif
	struct RELAYDNS_HEADER_S *rdns = (struct RELAYDNS_HEADER_S *)buf;
	qs = htons(rdns->q_count);

	// only supporting one query for now, not likely to ever support more than one.
	if(qs != 1)
		return(RELAYDNS_FALSE);

#ifdef RELAYDNS_DEBUG
	an = htons(rdns->a_count);
	au = htons(rdns->auth_count);
	ad = htons(rdns->add_count);

	printf("PARSE: ");
	for(i=0; i < len; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");

	printf("relaydns_head {\n");
	printf("  id=0x%X\n",            rdns->id);
	printf("    qr=%u (%s)\n",       (rdns->qr ? 1 : 0), (rdns->qr ? "is a Query Responce" : "is not a Query Responce"));
	printf("    opcode=0x%X\n", rdns->opcode);
	printf("    aa=%u (%s)\n",       (rdns->aa ? 1 : 0), (rdns->aa ? "is the Authoritive Server" : "is not the Authoritive Server"));
	printf("    tc=%u%s\n",          (rdns->tc ? 1 : 0), (rdns->tc ? " ( is Truncated)" : ""));
	printf("    rd=%u%s\n",          (rdns->rd ? 1 : 0), (rdns->rd ? " (Recursion Desired)" : ""));
	printf("    ra=%u%s\n",          (rdns->ra ? 1 : 0), (rdns->ra ? " (Recursion available)" : ""));
	printf("    z=0x%X\n",           rdns->z);
	printf("    rcode=0x%X\n",  rdns->rcode);
	printf("  }\n");
	printf("  qdcount=%u\n",         qs);
	printf("  ancount=%u\n",         an);
	printf("  nscount=%u\n",         au);
	printf("  arcount=%u\n",         ad);
	printf("}\n");
	printf("q_count=%d, a_count=%d, auth_count=%d, add_count=%d\n", qs, an, au, ad);
#endif

	return(relaydns_parse_query(buf+RELAYDNS_HEADER_SIZE, len-RELAYDNS_HEADER_SIZE, ip_addr));
}

// parse the query and build the response if applicable.
char relaydns_parse_query(unsigned char *buf, unsigned int len, struct in6_addr ip_addr) {
	unsigned char labels[RELAYDNS_MAX_LABELS][RELAYDNS_MAX_LABEL_SIZE+1] = {{0}};
	unsigned short labels_compress_markers[RELAYDNS_MAX_LABELS] = {0};
	unsigned char *ptr=buf, c=0;
	unsigned short ty=0, cl=0;
	int l=(int)len, labels_i=0;
#ifdef RELAYDNS_DEBUG
	unsigned int i;
#endif

	while(RELAYDNS_TRUE) {
		c = *ptr++;
		if(!c) {
			// "type" and "class" parts (16bit/short)
			if(l >= 5) {
				ty = (*ptr << 8) | *(ptr+1);
				cl = (*(ptr+2) << 8) | *(ptr+3);
				ptr +=4;
			}
			else
				return(RELAYDNS_FALSE); // must be malformed.
			break;
		}
		l -= c + 1;
		/* 4 bytes for the remainder of the packet (type(2)+class(2)) */
		if(l < 4 || c > RELAYDNS_MAX_LABEL_SIZE || labels_i >= RELAYDNS_MAX_LABELS)
			return(RELAYDNS_FALSE);
		labels_compress_markers[labels_i] = RELAYDNS_OFFSET_TO_SHORT(ptr-buf-1);
		memcpy(labels[labels_i++], ptr, c);
		ptr += c;
	}

	// we should assume at least "domain.tld" at a minimum.
	if(labels_i < 2)
		return(RELAYDNS_FALSE); // not really a request we want to respond to

	// we only support IN for this server.
	if(cl != RELAYDNS_CLASS_IN)
		return(RELAYDNS_FALSE); // still a normal packet

#ifdef RELAYDNS_DEBUG
	printf("LABELS[%d]: ", labels_i);
	for(i=0; i < labels_i; i++)
		printf("%s (%04X) ", labels[i], labels_compress_markers[i]);
	printf("\n");
#endif

	// annoying default behavior from windows.
	if(!strcasecmp((char *)labels[labels_i-1], "home"))
		return(RELAYDNS_TRUE); // still a normal packet

	// clip off any additional records after the query. (ie. additional records)
	rbuf.len = ptr - buf + RELAYDNS_HEADER_SIZE;

	switch(ty) {
		case RELAYDNS_TYPE_A:
			switch(labels_i) {
				case 2: // domain.com
					relaydns_resp_a_root(labels_compress_markers[labels_i - 2]);
					break;
				case 3: // sub.domain.com
					relaydns_resp_a_sub(labels_compress_markers[labels_i - 2], labels_compress_markers[0], labels[0]);
					break;
				case 4: // value.key.domain.com
					relaydns_resp_a_key_set(labels_compress_markers[labels_i - 3], labels_compress_markers[0], labels[1], labels[0]);
					break;
			}
			break;
		case RELAYDNS_TYPE_NS:
			// only makes sense for the root domain.
			if(labels_i == 2)
				relaydns_resp_ns(labels_compress_markers[labels_i - 2]);
			else
				relaydns_resp_none(RELAYDNS_RCODE_NXDOMAIN);
			break;
		case RELAYDNS_TYPE_SOA:
			// only makes sense for the root domain.
			if(labels_i == 2)
				relaydns_resp_soa(labels_compress_markers[labels_i - 2]);
			else
				relaydns_resp_none(RELAYDNS_RCODE_NXDOMAIN);
			break;
		case RELAYDNS_TYPE_MX:
			break;
		case RELAYDNS_TYPE_PTR:
			switch(labels_i) {
				case 3: // key.domain.com
					relaydns_resp_ptr_key_set(labels_compress_markers[labels_i - 2], labels_compress_markers[0], labels[0], ip_addr);
					break;
			}
			break;
		case RELAYDNS_TYPE_AAAA:
			switch(labels_i) {
				case 2: // domain.com
					relaydns_resp_aaaa_root(labels_compress_markers[labels_i - 2]);
					break;
				case 3: // sub.domain.com
					relaydns_resp_aaaa_sub(labels_compress_markers[labels_i - 2], labels_compress_markers[0], labels[0]);
					break;
				case 4: // value.key.domain.com
					relaydns_resp_aaaa_key_set(labels_compress_markers[labels_i - 3], labels_compress_markers[0], labels[1], labels[0]);
					break;
				default:
//					relaydns_resp_none(RELAYDNS_RCODE_NXDOMAIN);
					break;
			}
			break;
		case RELAYDNS_TYPE_CNAME:
			switch(labels_i) {
				case 2: // domain.com
					relaydns_resp_none(RELAYDNS_RCODE_NXDOMAIN);
					break;
				case 3: // key.domain.com
					relaydns_resp_cname_key_get(labels_compress_markers[labels_i - 2], labels_compress_markers[0], labels[0]);
					break;
				case 4: // value.key.domain.com
					relaydns_resp_cname_key_set(labels_compress_markers[labels_i - 3], labels_compress_markers[0], labels[1], labels[0]);
					break;
				default:
					relaydns_resp_none(RELAYDNS_RCODE_NXDOMAIN);
					break;
			}
			break;
		case RELAYDNS_TYPE_TXT:
			switch(labels_i) {
				case 2: // domain.com
					relaydns_resp_txt_root(labels_compress_markers[labels_i - 2]);
					break;
				case 3: // key.domain.com
					relaydns_resp_txt_key_get(labels_compress_markers[labels_i - 2], labels_compress_markers[0], labels[0]);
					break;
				default:
//					relaydns_resp_none(RELAYDNS_RCODE_NXDOMAIN);
					break;
			}
			break;
		case RELAYDNS_TYPE_ANY:
			switch(labels_i) {
				case 2: // domain.com
					relaydns_resp_any_root(labels_compress_markers[labels_i - 2]);
					break;
				case 3: // sub.domain.com
					relaydns_resp_any_sub(labels_compress_markers[labels_i - 2], labels_compress_markers[0], labels[0]);
					break;
				case 4: // value.key.domain.com
					relaydns_resp_any_key_set(labels_compress_markers[labels_i - 3], labels_compress_markers[0], labels[1], labels[0]);
					break;
				default:
//					relaydns_resp_none(RELAYDNS_RCODE_NXDOMAIN);
					break;
			}
			break;
#ifdef RELAYDNS_DEBUG
		default:
			printf("STUB: UNHANDLED TYPE: %d\n", ty);
			break;
#endif
	}
	return(RELAYDNS_TRUE);
}

