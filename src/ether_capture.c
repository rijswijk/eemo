/* $Id$ */

/*
 * Copyright (c) 2010-2011 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of SURFnet bv nor the names of its contributors 
 *    may be used to endorse or promote products derived from this 
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * The Extensible Ethernet Monitor (EEMO)
 * Ethernet packet capturing
 */

#include "config.h"
#include "eemo_log.h"
#include "ether_capture.h"
#include "ether_handler.h"
#include "eemo_config.h"
#include <stdio.h>
#include <signal.h>
#include <time.h>

#define SNAPLEN		65536

/* Global PCAP handle */
pcap_t* handle = NULL;

/* Total packet counter */
unsigned long long capture_ctr = 0;

/* Handled packet counter */
unsigned long long handled_ctr = 0;

/* Interval between logging of statistics */
int capture_stats_interval = 0;

/* Last time statistics were logged */
time_t last_capture_stats = 0;

/* Signal handler for exit signal */
void stop_signal_handler(int signum)
{
	INFO_MSG("Received request to exit");

	pcap_breakloop(handle);
}

/* PCAP callback handler */
void eemo_pcap_callback(u_char* user_ptr, const struct pcap_pkthdr* hdr, const u_char* capture_data)
{
	eemo_rv rv;

	/* Count the packet */
	capture_ctr++;

	/* Copy the captured data */
	eemo_packet_buf* packet = eemo_pbuf_new((u_char*) capture_data, hdr->len);

	/* Run it through the Ethernet handlers */
	rv = eemo_handle_ether_packet(packet);

	/* Conditionally increment the handled packet counter */
	if (rv == ERV_HANDLED)
	{
		handled_ctr++;
	}

	/* Check if we need to emit statistics */
	if (capture_stats_interval > 0)
	{
		if ((time(NULL) - last_capture_stats) >= capture_stats_interval)
		{
			last_capture_stats = time(NULL);

			INFO_MSG("Captured %llu packets %llu of which were handled by a plug-in", capture_ctr, handled_ctr);
		}
	}

	/* Free the packet data */
	eemo_pbuf_free(packet);
}

/* Capture and handle the specified number of packets on the specified interface, optionally using a filter */
eemo_rv eemo_capture_and_handle(const char* interface, int packet_count, const char* net_filter)
{
	const char* cap_if = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program packet_filter;
	handle = NULL;

	/* Reset counters */
	capture_ctr = handled_ctr = 0;
	last_capture_stats = time(NULL);

	/* Retrieve configuration */
	eemo_conf_get_int("capture", "stats_interval", &capture_stats_interval, 0);

	if (capture_stats_interval > 0)
	{
		INFO_MSG("Emitting capture statistics every %ds", capture_stats_interval);
	}

	/* Determine the default interface if none was specified */
	cap_if = (interface == NULL) ? pcap_lookupdev(errbuf) : interface;

	if (cap_if == NULL)
	{
		/* No capture interface available or specified */
		return ERV_ETH_NOT_EXIST;
	}

	INFO_MSG("Opening device %s for packet capture", cap_if);

	/* Open the device in promiscuous mode */
	handle = pcap_open_live(cap_if, SNAPLEN, 1, 1000, errbuf);

	if (handle == NULL)
	{
		/* Failed to open interface for capturing */
		return ERV_NO_ACCESS;
	}

	/* Compile and apply packet filter */
	if (net_filter != NULL)
	{
		if (pcap_compile(handle, &packet_filter, (char*) net_filter, 0, 0) == -1)
		{
			/* Failed to compile packet filter */
			pcap_close(handle);

			return ERV_INVALID_FILTER;
		}

		if (pcap_setfilter(handle, &packet_filter) == -1)
		{
			/* Failed to apply packet filter */
			pcap_freecode(&packet_filter);
			pcap_close(handle);

			return ERV_INVALID_FILTER;
		}

		pcap_freecode(&packet_filter);
	}

	/* Register the signal handler for termination */
	signal(SIGINT, stop_signal_handler);
	signal(SIGHUP, stop_signal_handler);
	signal(SIGTERM, stop_signal_handler);

	/* Capture the specified number of packets */
	INFO_MSG("Starting packet capture");

	if (pcap_loop(handle, packet_count, &eemo_pcap_callback, NULL) == -1)
	{
		pcap_close(handle);

		return ERV_CAPTURE_ERROR;
	}

	signal(SIGINT, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	INFO_MSG("Packet capture ended, captured %llu packets of which %llu were handled", capture_ctr, handled_ctr);

	pcap_close(handle);

	return ERV_OK;
}

