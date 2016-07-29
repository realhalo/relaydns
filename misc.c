/* [relaydns] misc.c :: various functions that don't have a home.
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

// convert an ipv6 address that is actually an ipv4 address to a standard ipv4 32bit integer. (returns 0 if not applicable)
unsigned int relaydns_misc_ip6addr_to_ip4addr(unsigned char *ip6addr) {
	unsigned int ret=0;

	// ipv6 version of an ipv4 address is always these 12 bytes followed by the next 4 bytes being the ipv4 version.
	if(!memcmp("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF", ip6addr, RELAYDNS_IP6_LEN-4))
		ret = (ip6addr[RELAYDNS_IP6_LEN-4] << 24)
		+ (ip6addr[RELAYDNS_IP6_LEN-3] << 16)
		+ (ip6addr[RELAYDNS_IP6_LEN-2] << 8)
		+ ip6addr[RELAYDNS_IP6_LEN-1];

	return(ret);
}

// setup all the signals we're monitoring.
void relaydns_misc_signal_setup() {
	signal(SIGBUS, relaydns_misc_signal);
	signal(SIGILL, relaydns_misc_signal);
	signal(SIGSEGV, relaydns_misc_signal);
	signal(SIGHUP, relaydns_misc_signal);
	signal(SIGQUIT, relaydns_misc_signal);
	signal(SIGTERM, relaydns_misc_signal);
	signal(SIGINT, relaydns_misc_signal);
	signal(SIGTSTP, relaydns_misc_signal);
	return;
}

// all-purpose signal handler.
void relaydns_misc_signal(int sig) {
	switch(sig) {
		case SIGHUP:
			relaydns_db_info_setup();
			break;
		case SIGBUS:
		case SIGILL:
		case SIGSEGV:
			exit(-1);
			break;
		case SIGQUIT:
		case SIGTERM:
		case SIGINT:
		case SIGTSTP:
			exit(0);
			break;
		default:
			break;
	}
	return;
}

// switch uid/gid/groups to a specified user. (don't abort if non-root or initgroups fails)
char relaydns_set_perm(uid_t uid, gid_t gid) {
	struct passwd *pwd;

	/* not root OR already the right user/gruop? skip. */
	if(getuid() > 0 || (getuid() == uid && getgid() == gid))
		return(RELAYDNS_TRUE);

	/* don't abort if this fails, not a good enough reason and could happen by accident. */
	if((pwd = getpwuid(uid)))
		initgroups(pwd->pw_name, gid);

	if(setgid(gid) || setuid(uid))
		return(RELAYDNS_FALSE);

	return(RELAYDNS_TRUE);
}

// help screen.
void relaydns_misc_print_usage(char *arg) {
	printf("usage: %s [vhfpHDTPRSXYZCgsioUG]\n\n", arg);
	printf("\t-v\t\t: print version information.\n");
	printf("\t-h\t\t: print this help screen.\n\n");

	printf("\t-f\t\t: run the server in the foreground.\n\n");

	printf("\t-p dns_port\t: set dns port to listen on. (%u)\n\n", RELAYDNS_PORT);

	printf("\t-H db_host\t: set database host. (\"%s\")\n", RELAYDNS_REDIS_HOST);
	printf("\t-D db_port\t: set database port. (%u)\n", RELAYDNS_REDIS_PORT);
	printf("\t-T db_timeout\t: exit after idle db socket activity, in seconds. (%us)\n", RELAYDNS_REDIS_TIMEOUT);
	printf("\t-P db_pass\t: if applicable, use password for db. (\"%s\")\n", RELAYDNS_REDIS_PASS);
	printf("\t-R db_retry\t: retry count if db get/set fails. (%u)\n", RELAYDNS_REDIS_RETRY);
	printf("\t-S db_sleep\t: sleep amount between retry attempts. (%uus)\n", RELAYDNS_REDIS_RETRY_USLEEP);
	printf("\t-X db_conf_db\t: set configuration database. (%u)\n", RELAYDNS_REDIS_DB_CONF);
	printf("\t-Y db_data_db\t: set data database. (%u)\n", RELAYDNS_REDIS_DB_DATA);
	printf("\t-Z db_reload\t: reload distributed config info after X seconds. (%u)\n", RELAYDNS_REDIS_RELOAD_EXP);
	printf("\t-C db_cmd\t: run an arbitrary command on the database and exit.\n\n");

	printf("\t-g flood_get\t: only allow X number of record pulls per second.\n");
	printf("\t-s flood_set\t: only allow X number of records created per second.\n");
	printf("\t-i flood_in\t: only allow X number incoming packets per second.\n");
	printf("\t-o flood_out\t: only allow X number outgoing packets per second.\n\n");

	printf("\t-U user_id\t: set uid, if running as root. (%u)\n", RELAYDNS_DEFAULT_UID);
	printf("\t-G group_id\t: set gid, if running as root. (%u)\n\n", RELAYDNS_DEFAULT_GID);

	return;
}

