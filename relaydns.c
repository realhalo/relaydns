/* [relaydns] relaydns.c :: data proxying authoritative dns daemon.
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

struct RELAYDNS_BINARYBUF_S rbuf = {{0}}, wbuf = {{0}};	// global read/write buffer.
struct RELAYDNS_DB_INFO_S relaydns_db_info = {{0}};		// static ips such as the NS ips.
struct RELAYDNS_DB_CONF_S relaydns_db_conf = {{0}};	// general database info (redis)
struct RELAYDNS_FLOOD_PROT_S relaydns_flood_prot = {0};	// flood protection limits.

extern char *optarg;

// MAIN
int main(int argc, char **argv) {
	int fd, optval, c;
	struct sockaddr_in6 saddr;
	socklen_t slen = sizeof(struct sockaddr_in6);
	char *dbcmd=NULL, daemonize=RELAYDNS_TRUE;
	unsigned short port=RELAYDNS_PORT;
	pid_t pid;
	uid_t uid = RELAYDNS_DEFAULT_UID;
	gid_t gid = RELAYDNS_DEFAULT_GID;

        relaydns_db_conf_set_defaults();

	while((c = getopt(argc, argv, "vhfp:H:D:T:P:R:S:X:Y:Z:C:s:g:i:o:U:G:")) != EOF) {
		switch(c) {
			case 'v':
				puts("relaydns version: "RELAYDNS_VERSION);
				exit(EXIT_SUCCESS);
				break;
			case 'h':
				relaydns_misc_print_usage(argv[0]);
				exit(EXIT_SUCCESS);
				break;
			case 'f':
				daemonize = RELAYDNS_FALSE;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'H':
				strncpy(relaydns_db_conf.host, optarg, RELAYDNS_STRSIZE-1);
				break;
			case 'D':
				relaydns_db_conf.port = atoi(optarg);
				break;
			case 'T':
				relaydns_db_conf.timeout = atoi(optarg);
				break;
			case 'P':
				strncpy(relaydns_db_conf.pass, optarg, RELAYDNS_STRSIZE-1);
				// subtle effort to hide the password from "ps" and such, still gives up the length.
				memset(optarg, '*', strlen(optarg));
				break;
			case 'R':
				relaydns_db_conf.retry = atoi(optarg);
				break;
			case 'S':
				relaydns_db_conf.retry_usleep = atoi(optarg);
				break;
			case 'X':
				relaydns_db_conf.db_conf = atoi(optarg);
				break;
			case 'Y':
				relaydns_db_conf.db_data = atoi(optarg);
				break;
			case 'Z':
				relaydns_db_conf.reload_exp = atoi(optarg);
				break;
			case 'C':
				dbcmd = optarg;
				break;
			case 's':
				relaydns_flood_prot.set_max = atoi(optarg);
				break;
			case 'g':
				relaydns_flood_prot.get_max = atoi(optarg);
				break;
			case 'i':
				relaydns_flood_prot.in_max = atoi(optarg);
				break;
			case 'o':
				relaydns_flood_prot.out_max = atoi(optarg);
				break;
			case 'U':
				uid = atoi(optarg);
				break;
			case 'G':
				gid = atoi(optarg);
				break;
			default:
				break;
		}
	}

	// initial db opening (with config loading), it will auto-reconnect on failures later on if needed.
	if(relaydns_db_connect(RELAYDNS_TRUE) != RELAYDNS_TRUE) {
		printf("couldn't connect to redis!\n");
		exit(EXIT_FAILURE);
	}
	// run -C "DBCOMMAND" if specified in command-line arguments, and exit.
	if(dbcmd) {
		relaydns_db_command(dbcmd);
		exit(EXIT_SUCCESS);
	}

	// using ipv6 sockets since they can cover both ipv4 and ipv6 at the same time.
	if ((fd=socket(PF_INET6, SOCK_DGRAM, 0)) < 0) {
		printf("ERROR opening socket\n");
		exit(EXIT_FAILURE);
	}
	optval = 0;
	// make sure IPV6_V6ONLY is disabled.
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&optval, sizeof(optval));
	// We don't want multiple listeners, so set SO_REUSEADDR/SO_REUSEPORT to 0
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(optval));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *)&optval, sizeof(optval));
#endif

	memset(&saddr, 0, slen);
	saddr.sin6_family = AF_INET6;
	saddr.sin6_addr = in6addr_any;
	saddr.sin6_port = htons(port);

	// bind to our dns port.
	if (bind(fd, (struct sockaddr *)&saddr, slen) < 0) {
		printf("ERROR binding\n");
		exit(EXIT_FAILURE);
	}

	if(relaydns_set_perm(uid, gid) == RELAYDNS_FALSE) {
		printf("ERROR binding\n");
		exit(EXIT_FAILURE);
	}

	if(daemonize == RELAYDNS_TRUE) {
		switch((pid=fork())) {
			case -1:
				printf("failed to fork into daemon mode.\n");
				return(EXIT_FAILURE);
				break;
			case 0:
				setsid();
				close(STDIN_FILENO);
				close(STDOUT_FILENO);
				close(STDERR_FILENO);

				// monitor specified signals.
				relaydns_misc_signal_setup();

				// start parsing packets (indefinitely)
				relaydns_parse_loop(fd, relaydns_db_conf.reload_exp);
				break;
			default:
				printf("pid: %d\n", pid);
		}
	}
	// run in the foreground.
	else {
		// monitor specified signals.
		relaydns_misc_signal_setup();

		// start parsing packets (indefinitely)
		relaydns_parse_loop(fd, relaydns_db_conf.reload_exp);
	}

	return(EXIT_SUCCESS);
}
