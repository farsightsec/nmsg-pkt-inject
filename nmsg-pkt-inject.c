#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>
#include <nmsg/isc/defs.h>
#include <nmsg/isc/pkt.pb-c.h>

#include <pcap.h>

#include "argv.h"
#include "atomic.h"

#define STATS_FREQUENCY		60

static argv_array_t		r_chan, r_nmsg, r_sock;
static const char *		iface;

static nmsg_io_t		io;
static pcap_t *			pcap;
static pthread_t		thr_stats;
static volatile bool		shut_down;
static bool			is_live;

static const char		*eth_broadcast = "\xFF\xFF\xFF\xFF\xFF\xFF";

/* counters */

static atomic_t			count_output;

/* macros */

#define process_args_loop_io(arry, func) do { \
	for (int i = 0; i < ARGV_ARRAY_COUNT(arry); i++) \
		func(io, *ARGV_ARRAY_ENTRY_P(arry, char *, i), NULL); \
} while(0)

#define process_args_loop(arry, func) do { \
	for (int i = 0; i < ARGV_ARRAY_COUNT(arry); i++) \
		func(*ARGV_ARRAY_ENTRY_P(arry, char *, i)); \
} while(0)

static argv_t args[] = {
	{ 'C', "readchan",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&r_chan,
		"channel",
		"read nmsg data from channel" },

	{ 'r', "readnmsg",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&r_nmsg,
		"file",
		"read nmsg data from file" },

	{ 'l', "readsock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&r_sock,
		"so",
		"read nmsg data from socket (addr/port)" },

	{ 'o', "interface",
		ARGV_CHAR_P,
		&iface,
		"iface",
		"output ISC/pkt data to ethernet interface" },

	{ ARGV_LAST, 0, 0, 0, 0, 0 }
};

static void
process_args(int argc, char **argv) {
	unsigned n_inputs = 0;

	argv_process(args, argc, argv);

	n_inputs += ARGV_ARRAY_COUNT(r_chan);
	n_inputs += ARGV_ARRAY_COUNT(r_nmsg);
	n_inputs += ARGV_ARRAY_COUNT(r_sock);

	if (n_inputs < 1 || iface == NULL) {
		argv_usage(args, ARGV_USAGE_LONG);
		exit(EXIT_FAILURE);
	}

	if (ARGV_ARRAY_COUNT(r_chan) + ARGV_ARRAY_COUNT(r_sock) > 0)
		is_live = true;
	
	process_args_loop_io(r_chan, nmsg_io_add_input_channel);
	process_args_loop_io(r_sock, nmsg_io_add_input_sockspec);
	process_args_loop_io(r_nmsg, nmsg_io_add_input_fname);
}

static void
process_msg(nmsg_message_t msg) {
	Nmsg__Isc__Pkt *pkt;
	int rc;

	pkt = (Nmsg__Isc__Pkt *) nmsg_message_get_payload(msg);
	assert(pkt != NULL);
	assert(pkt->has_len_frame);
	assert(pkt->payload.data != NULL);
	assert(pkt->payload.len == pkt->len_frame);

	memcpy(pkt->payload.data, eth_broadcast, 6);

	rc = pcap_inject(pcap, pkt->payload.data, pkt->payload.len);
	if (rc == -1) {
		pcap_perror(pcap, argv_program);
		exit(EXIT_FAILURE);
	}

	atomic_inc(&count_output);
}

static void
nmsg_callback(nmsg_message_t msg, void *user) {
	if (nmsg_message_get_vid(msg) == NMSG_VENDOR_ISC_ID &&
	    nmsg_message_get_msgtype(msg) == NMSG_VENDOR_ISC_PKT_ID)
	{
		process_msg(msg);
	}

	nmsg_message_destroy(&msg);
}

static void
shutdown_handler(int signum __attribute__((unused))) {
	fprintf(stderr, "signalled break\n");
	if (shut_down == false) {
		nmsg_io_breakloop(io);
		shut_down = true;
	}
}

static void
print_stats(void) {
	int my_count_output = atomic_zero(&count_output);

	fprintf(stderr, "count_output= %u\n", my_count_output);
}

static void *
stats_thread(void *user) {
	struct timespec ts = { .tv_sec = STATS_FREQUENCY, .tv_nsec = 0 };

	for (;;) {
		nmsg_timespec_sleep(&ts);
		if (shut_down)
			break;
		print_stats();
	}

	return (NULL);
}

void
setup_threads(void) {
	if (is_live) {
		/* create stats thread */
		assert(pthread_create(&thr_stats, NULL, stats_thread, NULL) == 0);
	}
}

void
cleanup(void) {
	nmsg_io_destroy(&io);
	print_stats();
	argv_cleanup(args);
}

void
setup_pcap(void) {
	char errbuf[PCAP_ERRBUF_SIZE];
	int rc;

	pcap = pcap_create(iface, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "%s: unable to add pcap interface output %s: %s\n",
			argv_program, iface, errbuf);
		exit(EXIT_FAILURE);
	}

	rc = pcap_set_snaplen(pcap, 60);
	if (rc != 0) {
		fprintf(stderr, "%s: pcap_set_snaplen() failed\n", argv_program);
		exit(EXIT_FAILURE);
	}

	rc = pcap_activate(pcap);
	if (rc != 0) {
		fprintf(stderr, "%s: pcap_activate() failed\n", argv_program);
		exit(EXIT_FAILURE);
	}
}

void
setup_io(void) {
	nmsg_output_t output_cb;
	nmsg_res res;

	io = nmsg_io_init();
	assert(io != NULL);

	output_cb = nmsg_output_open_callback(nmsg_callback, NULL);
	if (output_cb == NULL)
		errx(EXIT_FAILURE, "nmsg_output_open_callback() failed");
	res = nmsg_io_add_output(io, output_cb, NULL);
	if (res != nmsg_res_success)
		errx(EXIT_FAILURE, "nmsg_io_add_output() failed: %s", nmsg_res_lookup(res));
}

int
main(int argc, char **argv) {
	assert(nmsg_init() == nmsg_res_success);
	assert(nmsg_msgmod_lookup_byname("ISC", "pkt") != NULL);

	setup_io();
	process_args(argc, argv);
	setup_pcap();
	setup_threads();

	signal(SIGINT, shutdown_handler);
	signal(SIGTERM, shutdown_handler);

	if (nmsg_io_loop(io) != nmsg_res_success)
		errx(EXIT_FAILURE, "nmsg_io_loop() failed");

	cleanup();

	return (EXIT_SUCCESS);
}
