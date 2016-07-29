/* [relaydns] add.c :: mechanisms to add responses to the output buffer.
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
extern struct RELAYDNS_BINARYBUF_S rbuf;
extern struct RELAYDNS_BINARYBUF_S wbuf;

// convert dot-notation domain name to length-notation format on a pre-existing buffer.
// SECURITY: buf write-out pointer must have at least strlen(name)+2 bytes remaining to avoid an overflow, THIS FUNCTION DOES NOT VERIFY!
unsigned int relaydns_add_name2wbuf(unsigned char *name, unsigned char **wbufptr) {
	unsigned char *wptr, *nptr, *eptr; // wptr=current, nptr=dot, eptr=end
	unsigned int len = strlen((char *)name);
	wptr = nptr = *wbufptr;		// set wptr/nptr to start are the beginning of the output buffer (wbuf).
	wptr++;				// first character is for the first label's length.
	memcpy(wptr, name, len);	// block copy the src->dst with no manipulation, manipulate after the fact.
	eptr = *wbufptr + len + 1;	// extra 1 for the first label length...
	*eptr++ = 0; 			// ...and another extra 1 for the final null byte, which we'll fill now.
	while(wptr < eptr) {
		if(!*wptr || *wptr == '.') {
			*nptr = (unsigned char)(wptr-nptr-1);	// write the dot-to-octet character conversion.
			nptr = wptr;				// set the current dot for the next iteration.
		}
		wptr++;
	}
	return(wptr - *wbufptr);
}

// fill in the response packet with the original header: id, flags, counts, etc.
unsigned int relaydns_add_boilerplate() {
	memcpy(wbuf.data, rbuf.data, rbuf.len);
	memset(wbuf.data+2, 0, 10);	// clear all flags and counts.
	wbuf.data[5] = 1;		// set question count back to one.
	return(rbuf.len);
}

// add name-based (generally CNAME, but multi-purpose) answer to the write buffer.
unsigned int relaydns_add_name(unsigned short relaydns_type, unsigned char *name, unsigned short name_offset, unsigned char *cname, unsigned short cname_offset, unsigned char **wptr_start) {
	unsigned char *wptr=*wptr_start, *tptr;

	if(name)
		wptr += relaydns_add_name2wbuf(name, &wptr);
	if(name_offset) {
		if(name && wptr > *wptr_start && !*(wptr-1))
			wptr--; // remove the null byte
		*((unsigned short *)wptr) = htons(name_offset);
		wptr += 2;
	}

	*((unsigned short *)wptr) = htons(relaydns_type);
	wptr += 2;
	*((unsigned short *)wptr) = htons(RELAYDNS_CLASS_IN);
	wptr += 2;
	*((unsigned int *)wptr) = htonl(RELAYDNS_MISC_TTL);
	wptr += 4;

	// mark pointer where the size goes and fill it in after.
	tptr = wptr;
	wptr += 2;

	if(cname)
		wptr += relaydns_add_name2wbuf(cname, &wptr);
	if(cname_offset) {
		if(cname && wptr > *wptr_start && !*(wptr-1))
			wptr--; // remove the null byte
		*((unsigned short *)wptr) = htons(cname_offset);
		wptr += 2;
	}

	// ... fill in the size now that we know how long it is.
	*((unsigned short *)tptr) = htons(wptr - tptr - 2);

	return(wptr - *wptr_start);
}

// add SOA answer to the write buffer.
unsigned int relaydns_add_soa(unsigned short root_offset, unsigned char **wptr_start) {
	unsigned int nslen = strlen(RELAYDNS_NS_PREFIX);
	unsigned char *wptr=*wptr_start;

	*((unsigned short *)wptr) = htons(root_offset); // root domain name included in request.
	wptr += 2;
	*((unsigned short *)wptr) = htons(RELAYDNS_TYPE_SOA);
	wptr += 2;
	*((unsigned short *)wptr) = htons(RELAYDNS_CLASS_IN);
	wptr += 2;
	*((unsigned int *)wptr) = htonl(RELAYDNS_SOA_TTL); // TTL
	wptr += 4;

/*
	size layout:
	primary ns: 1b len + nslen + 1b digit + 2b compression
	responsible auth: 2b compression
	serial: 4b
	refresh: 4b
	retry: 4b
	expire: 4b
	min: 4b
*/
	*((unsigned short *)wptr) = htons(nslen + 26); // size
	wptr += 2;

	// primary ns: 1b len + nslen + 1b digit + 2b compression
	*wptr++ = (unsigned char)(nslen + 1);
	memcpy(wptr, RELAYDNS_NS_PREFIX, nslen);
	wptr += nslen;
	*wptr++ = '0'; // NS0 is always the primary dns.
	*((unsigned short *)wptr) = htons(root_offset);
	wptr += 2;

	// responsible auth: compression to root domain name included in request.
	*((unsigned short *)wptr) = htons(root_offset);
	wptr += 2;

	// serial #
	*((unsigned int *)wptr) = htonl(RELAYDNS_SOA_SERIAL);
	wptr += 4;

	// refresh, retry, expire, minimum ttls
	*((unsigned int *)wptr) = htonl(RELAYDNS_SOA_REFRESH_TTL);
	wptr += 4;
	*((unsigned int *)wptr) = htonl(RELAYDNS_SOA_RETRY_TTL);
	wptr += 4;
	*((unsigned int *)wptr) = htonl(RELAYDNS_SOA_EXPIRE_TTL);
	wptr += 4;
	*((unsigned int *)wptr) = htonl(RELAYDNS_SOA_MINIMUM_TTL);
	wptr += 4;
	return(wptr - *wptr_start);
}

// add NS answer to the write buffer.
unsigned int relaydns_add_ns(unsigned short root_offset, unsigned char **wptr_start) {
	unsigned int nslen = strlen(RELAYDNS_NS_PREFIX), i;
	unsigned char *wptr=*wptr_start;

	for(i=0; i < relaydns_db_info.ns_total; i++) {
		*((unsigned short *)wptr) = htons(root_offset); // root domain name included in request.
		wptr += 2;
		*((unsigned short *)wptr) = htons(RELAYDNS_TYPE_NS);
		wptr += 2;
		*((unsigned short *)wptr) = htons(RELAYDNS_CLASS_IN);
		wptr += 2;
		*((unsigned int *)wptr) = htonl(RELAYDNS_MISC_TTL); // TTL
		wptr += 4;
		*((unsigned short *)wptr) = htons(nslen + 4); // size, nslen + 1b digit + 1b dot len encoded + 2b compression offset
		wptr += 2;
		*wptr++ = (unsigned char)(nslen + 1); // length of the "NS1" string to come.
		memcpy(wptr, RELAYDNS_NS_PREFIX, nslen);
		wptr += nslen;
		*wptr++ = 0x30 + i; // "ie. NS1"
		*((unsigned short *)wptr) = htons(root_offset); // compression to root domain name included in request.
		wptr += 2;
	}
	return(wptr - *wptr_start);
}

// add A answer to the write buffer.
unsigned int relaydns_add_a(unsigned short root_offset, unsigned int ip, unsigned char **wptr_start) {
	unsigned char *wptr=*wptr_start;
	*((unsigned short *)wptr) = htons(root_offset); // root domain name included in request.
	wptr += 2;
	*((unsigned short *)wptr) = htons(RELAYDNS_TYPE_A);
	wptr += 2;
	*((unsigned short *)wptr) = htons(RELAYDNS_CLASS_IN);
	wptr += 2;
	*((unsigned int *)wptr) = htonl(RELAYDNS_MISC_TTL); // TTL
	wptr += 4;
	*((unsigned short *)wptr) = htons(RELAYDNS_IP_LEN); // IP LEN
	wptr += 2;
	*((unsigned int *)wptr) = ip; // IP
	wptr += 4;
	return(wptr - *wptr_start);
}

// add AAAA answer to the write buffer.
unsigned int relaydns_add_aaaa(unsigned short root_offset, unsigned char *ip6, unsigned char **wptr_start, char convert_ip6_to_bin) {
	unsigned char ip6buf[RELAYDNS_IP6_LEN], *wptr=*wptr_start;
	*((unsigned short *)wptr) = htons(root_offset); // root domain name included in request.
	wptr += 2;
	*((unsigned short *)wptr) = htons(RELAYDNS_TYPE_AAAA);
	wptr += 2;
	*((unsigned short *)wptr) = htons(RELAYDNS_CLASS_IN);
	wptr += 2;
	*((unsigned int *)wptr) = htonl(RELAYDNS_MISC_TTL); // TTL
	wptr += 4;
	*((unsigned short *)wptr) = htons(RELAYDNS_IP6_LEN); // IP LEN
	wptr += 2;
	if(convert_ip6_to_bin) {
		if(inet_pton(AF_INET6, (char *)ip6, ip6buf) > 0)
			memcpy(wptr, ip6buf, RELAYDNS_IP6_LEN); //ip6
		else // error
			memset(wptr, 0, RELAYDNS_IP6_LEN); //ip6
	}
	else
		memcpy(wptr, (unsigned char *)ip6, RELAYDNS_IP6_LEN); //ip6
	wptr += RELAYDNS_IP6_LEN;
	return(wptr - *wptr_start);
}

// add TXT answer to the write buffer.
unsigned int relaydns_add_txt(unsigned char *txt, unsigned short root_offset, unsigned char **wptr_start) {
	int len = strlen((char *)txt);
	unsigned char *wptr=*wptr_start;
	*((unsigned short *)wptr) = htons(root_offset); // root domain name included in request.
	wptr += 2;
	*((unsigned short *)wptr) = htons(RELAYDNS_TYPE_TXT);
	wptr += 2;
	*((unsigned short *)wptr) = htons(RELAYDNS_CLASS_IN);
	wptr += 2;
	*((unsigned int *)wptr) = htonl(RELAYDNS_MISC_TTL); // TTL
	wptr += 4;
	*((unsigned short *)wptr) = htons(len+1); // LEN (+1 for TXTLEN)
	wptr += 2;

	// fill in the text data.
	*wptr++ = (unsigned char)len; // TXT LEN
	memcpy(wptr, txt, len); // TXT DATA
	wptr += len;

	return(wptr - *wptr_start);
}
