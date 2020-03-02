/*
 * Copyright (c) 2020 NLnet Labs
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
 * DNS statistics plug-in query counter code
 */

#include "config.h"
#include "eemo.h"
#include "eemo_log.h"
#include "eemo_respstats_stats.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#define IP_ANY	"*"

/* The counters */

/* IP types */
struct
{
	unsigned long long V4;
	unsigned long long V6;
}
iptype_ctr;

/* Transmission protocol types */
struct
{
	unsigned long long UDP[2];
	unsigned long long TCP[2];
}
proto_ctr;

/* EDNS0 */
struct
{
	unsigned long long EDNS0_NO[2];
	unsigned long long EDNS0_BELOW_512[2];
	unsigned long long EDNS0_512_TO_999[2];
	unsigned long long EDNS0_1000_TO_1499[2];
	unsigned long long EDNS0_1500_TO_1999[2];
	unsigned long long EDNS0_2000_TO_2499[2];
	unsigned long long EDNS0_2500_TO_2999[2];
	unsigned long long EDNS0_3000_TO_3499[2];
	unsigned long long EDNS0_3500_TO_3999[2];
	unsigned long long EDNS0_4000_TO_4499[2];
	unsigned long long EDNS0_ABOVE_4500[2];
	unsigned long long EDNS0_DO_SET[2];
	unsigned long long EDNS0_DO_UNSET[2];
	unsigned long long EDNS0_W_ECS[2];
	unsigned long long EDNS0_WO_ECS[2];
	unsigned long long EDNS0_EXP_OPT[2];
}
edns0_ctr;

/* Response size */
struct
{
	unsigned long long RSIZE_BELOW_512[2];
	unsigned long long RSIZE_512_TO_1023[2];
	unsigned long long RSIZE_1024_TO_1535[2];
	unsigned long long RSIZE_1536_TO_2047[2];
	unsigned long long RSIZE_2048_TO_2559[2];
	unsigned long long RSIZE_2560_TO_3071[2];
	unsigned long long RSIZE_3072_TO_3583[2];
	unsigned long long RSIZE_3584_TO_4095[2];
	unsigned long long RSIZE_ABOVE_4096[2];
	unsigned long long RSIZE_TOTAL[2];
	unsigned long long RSIZE_COUNTED[2];
}
rsize_ctr;

/* Response fragmentation */
struct
{
	unsigned long long R_FRAG[2];
	unsigned long long R_UNFRAG[2];
}
rfrag_ctr;

/* Response flags */
struct
{
	unsigned long long RFLAG_TC[2];
}
rflags_ctr;

/* Configuration */
int	stat_emit_interval	= 0;
char*	stat_file		= NULL;
int	stat_append		= 0;
int	stat_reset		= 1;

/* Statistics file */
FILE*	stat_fp			= NULL;

/* Write statistics to file */
void write_stats(void)
{
	/* Open the file for writing if necessary */
	if (!stat_append)
	{
		stat_fp = fopen(stat_file, "w");
	}

	if (stat_fp != NULL)
	{
		int	i = 0;

		fprintf(stat_fp, "{ ");
		fprintf(stat_fp, "\"timestamp\": %lu, ", time(NULL));
		fprintf(stat_fp, "\"v4_count\": %llu, ", iptype_ctr.V4);
		fprintf(stat_fp, "\"v6_count\": %llu, ", iptype_ctr.V6);

		for (i = 0; i < 2; i++)
		{
			if (i == 0)
			{
				fprintf(stat_fp, "\"v4\": { ");
			}
			else
			{
				fprintf(stat_fp, "\"v6\": { ");
			}

			fprintf(stat_fp, "\"udp\": %llu, ", proto_ctr.UDP[i]);
			fprintf(stat_fp, "\"tcp\": %llu, ", proto_ctr.TCP[i]);
			
			fprintf(stat_fp, "\"unfragmented\": %llu, ", rfrag_ctr.R_UNFRAG[i]);
			fprintf(stat_fp, "\"fragmented\": %llu, ", rfrag_ctr.R_FRAG[i]);

			fprintf(stat_fp, "\"truncated\": %llu, ", rflags_ctr.RFLAG_TC[i]);

			fprintf(stat_fp, "\"size\": { ");
			fprintf(stat_fp, "\"lt_512\": %llu, ", rsize_ctr.RSIZE_BELOW_512[i]);
			fprintf(stat_fp, "\"512_to_1023\": %llu, ", rsize_ctr.RSIZE_512_TO_1023[i]);
			fprintf(stat_fp, "\"1024_to_1535\": %llu, ", rsize_ctr.RSIZE_1024_TO_1535[i]);
			fprintf(stat_fp, "\"1536_to_2047\": %llu, ", rsize_ctr.RSIZE_1536_TO_2047[i]);
			fprintf(stat_fp, "\"2048_to_2559\": %llu, ", rsize_ctr.RSIZE_2048_TO_2559[i]);
			fprintf(stat_fp, "\"2560_to_3071\": %llu, ", rsize_ctr.RSIZE_2560_TO_3071[i]);
			fprintf(stat_fp, "\"3072_to_3583\": %llu, ", rsize_ctr.RSIZE_3072_TO_3583[i]);
			fprintf(stat_fp, "\"3584_to_4095\": %llu, ", rsize_ctr.RSIZE_3584_TO_4095[i]);
			fprintf(stat_fp, "\"gt_4096\": %llu", rsize_ctr.RSIZE_ABOVE_4096[i]);
			fprintf(stat_fp, "}, ");

			fprintf(stat_fp, "\"edns0\": { ");
			fprintf(stat_fp, "\"no_edns\": %llu, ", edns0_ctr.EDNS0_NO[i]);
			fprintf(stat_fp, "\"edns_buf_lt_512\": %llu, ", edns0_ctr.EDNS0_BELOW_512[i]);
			fprintf(stat_fp, "\"edns_buf_512_to_999\": %llu, ", edns0_ctr.EDNS0_512_TO_999[i]);
			fprintf(stat_fp, "\"edns_buf_1000_to_1499\": %llu, ", edns0_ctr.EDNS0_1000_TO_1499[i]);
			fprintf(stat_fp, "\"edns_buf_1500_to_1999\": %llu, ", edns0_ctr.EDNS0_1500_TO_1999[i]);
			fprintf(stat_fp, "\"edns_buf_2000_to_2499\": %llu, ", edns0_ctr.EDNS0_2000_TO_2499[i]);
			fprintf(stat_fp, "\"edns_buf_2500_to_2999\": %llu, ", edns0_ctr.EDNS0_2500_TO_2999[i]);
			fprintf(stat_fp, "\"edns_buf_3000_to_3499\": %llu, ", edns0_ctr.EDNS0_3000_TO_3499[i]);
			fprintf(stat_fp, "\"edns_buf_3500_to_3999\": %llu, ", edns0_ctr.EDNS0_3500_TO_3999[i]);
			fprintf(stat_fp, "\"edns_buf_4000_to_4499\": %llu, ", edns0_ctr.EDNS0_4000_TO_4499[i]);
			fprintf(stat_fp, "\"edns_buf_gt_4500\": %llu, ", edns0_ctr.EDNS0_ABOVE_4500[i]);
			fprintf(stat_fp, "\"do_set\": %llu, ", edns0_ctr.EDNS0_DO_SET[i]);
			fprintf(stat_fp, "\"do_unset\": %llu, ", edns0_ctr.EDNS0_DO_UNSET[i]);
			fprintf(stat_fp, "\"ecs\": %llu, ", edns0_ctr.EDNS0_W_ECS[i]);
			fprintf(stat_fp, "\"no_ecs\": %llu", edns0_ctr.EDNS0_WO_ECS[i]);
			fprintf(stat_fp, "} ");

			fprintf(stat_fp, "}");

			if (i == 0) fprintf(stat_fp, ", "); else fprintf(stat_fp, " ");
		}

		fprintf(stat_fp, "}\n");
		fflush(stat_fp);

		/* Reset the statistics if necessary */
		if (stat_reset)
		{
			eemo_respstats_stats_reset();
		}
	}

	/* Close the file if necessary */
	if (!stat_append && (stat_fp != NULL))
	{
		fclose(stat_fp);
	}
}

static void eemo_respstats_stats_reset_alarm(void)
{
	if (stat_emit_interval > 0)
	{
		time_t	now		= time(NULL);
		time_t	next		= now + stat_emit_interval;
		int	alarm_interval	= ((next / stat_emit_interval) * stat_emit_interval) - now;

		DEBUG_MSG("Next statistics dump after %ds", alarm_interval);
		alarm(alarm_interval);
	}
}

/* Signal handler for alarms & user signals */
void signal_handler(int signum)
{
	if (signum == SIGUSR1)
	{
		DEBUG_MSG("Received user signal to dump statistics");
	}
	else if (signum == SIGALRM)
	{
		DEBUG_MSG("Received automated alarm to dump statistics");
	}
	
	/* Write statistics to file */
	write_stats();

	/* Set the new alarm if necessary */
	if (signum == SIGALRM)
	{
		eemo_respstats_stats_reset_alarm();
	}
}

/* Reset statistics */
void eemo_respstats_stats_reset(void)
{
	memset(&iptype_ctr, 0, sizeof(iptype_ctr));
	memset(&proto_ctr, 0, sizeof(proto_ctr));
	memset(&edns0_ctr, 0, sizeof(edns0_ctr));
	memset(&rsize_ctr, 0, sizeof(rsize_ctr));
	memset(&rfrag_ctr, 0, sizeof(rfrag_ctr));
	memset(&rflags_ctr, 0, sizeof(rflags_ctr));

	DEBUG_MSG("DNS response statistics reset");
}

/* Initialise the DNS query counter module */
void eemo_respstats_stats_init(int emit_interval, char* stats_file, int append_file, int reset)
{
	stat_emit_interval = emit_interval;

	INFO_MSG("Emitting statistics every %d seconds", emit_interval);

	stat_file = stats_file;

	INFO_MSG("Writing statistics to the file called %s", stat_file);

	stat_append = append_file;

	INFO_MSG("Will %soverwrite the file when new statistics are available", stat_append ? "not " : "");

	stat_reset = reset;

	INFO_MSG("Will %sreset statistics once they have been written to file", stat_reset ? "" : "not ");

	if (stat_append)
	{
		stat_fp = fopen(stat_file, "w");

		if (stat_fp != NULL)
		{
			INFO_MSG("Opened %s to write statistics to", stat_file);
		}
		else
		{
			ERROR_MSG("Failed to open %s for writing", stat_file);
		}
	}

	eemo_respstats_stats_reset();
	
	/* Register signal handler */
	signal(SIGUSR1, signal_handler);
	signal(SIGALRM, signal_handler);

	/* Set the alarm */
	eemo_respstats_stats_reset_alarm();
}

/* Uninitialise the DNS query counter module */
void eemo_respstats_stats_uninit(eemo_conf_free_string_array_fn free_strings)
{
	/* Unregister signal handlers */
	alarm(0);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGALRM, SIG_DFL);
	
	/* Write statistics one more time before exiting */
	write_stats();

	/* Close the file */
	if (stat_append && (stat_fp != NULL))
	{
		fclose(stat_fp);

		DEBUG_MSG("Closed %s", stat_file);
	}
	else
	{
		INFO_MSG("Statistics file %s was not open", stat_file);
	}

	free(stat_file);
}

/* Handle DNS query packets and log the statistics */
eemo_rv eemo_respstats_stats_handleqr(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* dns_packet)
{
	if (dns_packet->qr_flag)
	{
		/* This is a response */
		int stats_index = 0;

		switch(ip_info.ip_type)
		{
		case IP_TYPE_V4:
			iptype_ctr.V4++;
			stats_index = 0;
			break;
		case IP_TYPE_V6:
			iptype_ctr.V6++;
			stats_index = 1;
			break;
		default:
			ERROR_MSG("Unknown IP type");
			return ERV_SKIPPED;
		}


		/* Count only valid responses */
		if (!dns_packet->is_valid)
		{
			return ERV_SKIPPED;
		}

		/* Count fragmented vs. unfragmented responses */
		if (ip_info.is_fragment || ip_info.is_reassembled)
		{
			rfrag_ctr.R_FRAG[stats_index]++;
		}
		else
		{
			rfrag_ctr.R_UNFRAG[stats_index]++;
		}

		if (is_tcp)
		{
			proto_ctr.TCP[stats_index]++;
		}
		else
		{
			proto_ctr.UDP[stats_index]++;
		}

		/* Log EDNS0 data */
		if (dns_packet->has_edns0)
		{
			if (dns_packet->edns0_do)
			{
				edns0_ctr.EDNS0_DO_SET[stats_index]++;
			}
			else
			{
				edns0_ctr.EDNS0_DO_UNSET[stats_index]++;
			}

			/* Log EDNS0 buffer size */
			if (dns_packet->edns0_max_size < 512)
			{
				edns0_ctr.EDNS0_BELOW_512[stats_index]++;
			}
			else if ((dns_packet->edns0_max_size >= 512) && (dns_packet->edns0_max_size < 1000))
			{
				edns0_ctr.EDNS0_512_TO_999[stats_index]++;
			}
			else if ((dns_packet->edns0_max_size >= 1000) && (dns_packet->edns0_max_size < 1500))
			{
				edns0_ctr.EDNS0_1000_TO_1499[stats_index]++;
			}
			else if ((dns_packet->edns0_max_size >= 1500) && (dns_packet->edns0_max_size < 2000))
			{
				edns0_ctr.EDNS0_1500_TO_1999[stats_index]++;
			}
			else if ((dns_packet->edns0_max_size >= 2000) && (dns_packet->edns0_max_size < 2500))
			{
				edns0_ctr.EDNS0_2000_TO_2499[stats_index]++;
			}
			else if ((dns_packet->edns0_max_size >= 2500) && (dns_packet->edns0_max_size < 3000))
			{
				edns0_ctr.EDNS0_2500_TO_2999[stats_index]++;
			}
			else if ((dns_packet->edns0_max_size >= 3000) && (dns_packet->edns0_max_size < 3500))
			{
				edns0_ctr.EDNS0_3000_TO_3499[stats_index]++;
			}
			else if ((dns_packet->edns0_max_size >= 3500) && (dns_packet->edns0_max_size < 4000))
			{
				edns0_ctr.EDNS0_3500_TO_3999[stats_index]++;
			}
			else if ((dns_packet->edns0_max_size >= 4000) && (dns_packet->edns0_max_size < 4500))
			{
				edns0_ctr.EDNS0_4000_TO_4499[stats_index]++;
			}
			else
			{
				edns0_ctr.EDNS0_ABOVE_4500[stats_index]++;
			}

			if (dns_packet->has_edns0_client_subnet)
			{
				edns0_ctr.EDNS0_W_ECS[stats_index]++;
				INFO_MSG("Response with EDNS Client Subnet received querying for %s from %s for scope %s/%d", dns_packet->questions->qname, ip_info.ip_src, dns_packet->edns0_client_subnet_ip, dns_packet->edns0_client_subnet_res_scope);
			}
			else
			{
				edns0_ctr.EDNS0_WO_ECS[stats_index]++;
			}

			if (dns_packet->has_edns0_exp_opt)
			{
				edns0_ctr.EDNS0_EXP_OPT[stats_index]++;
			}
		}
		else
		{
			edns0_ctr.EDNS0_NO[stats_index]++;
		}

		/* Count response size in buckets; only count response > 0 bytes */
		if (dns_packet->udp_len > 0)
		{
			if (dns_packet->udp_len < 512)
			{
				rsize_ctr.RSIZE_BELOW_512[stats_index]++;
			}
			else if (dns_packet->udp_len < 1024)
			{
				rsize_ctr.RSIZE_512_TO_1023[stats_index]++;
			}
			else if (dns_packet->udp_len < 1536)
			{
				rsize_ctr.RSIZE_1024_TO_1535[stats_index]++;
			}
			else if (dns_packet->udp_len < 2048)
			{
				rsize_ctr.RSIZE_1536_TO_2047[stats_index]++;
			}
			else if (dns_packet->udp_len < 2560)
			{
				rsize_ctr.RSIZE_2048_TO_2559[stats_index]++;
			}
			else if (dns_packet->udp_len < 3072)
			{
				rsize_ctr.RSIZE_2560_TO_3071[stats_index]++;
			}
			else if (dns_packet->udp_len < 3584)
			{
				rsize_ctr.RSIZE_3072_TO_3583[stats_index]++;
			}
			else if (dns_packet->udp_len < 4096)
			{
				rsize_ctr.RSIZE_3584_TO_4095[stats_index]++;
			}
			else
			{
				rsize_ctr.RSIZE_ABOVE_4096[stats_index]++;
			}

			rsize_ctr.RSIZE_TOTAL[stats_index] += dns_packet->udp_len;
			rsize_ctr.RSIZE_COUNTED[stats_index]++;
		}

		/* Count flags */
		if (dns_packet->tc_flag) rflags_ctr.RFLAG_TC[stats_index]++;

		return ERV_HANDLED;
	}
	else
	{
		/* This is a query */
		return ERV_SKIPPED;
	}
}

