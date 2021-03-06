/*
 * Copyright (c) 2010-2017 SURFnet bv
 * Copyright (c) 2017 Roland van Rijswijk-Deij
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
 * DNS de-NAT data extraction plugin
 */

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include "utlist.h"
#include "uthash.h"
#include "eemo.h"
#include "eemo_api.h"
#include "eemo_plugin_log.h"
#include "dns_handler.h"
#include "dns_parser.h"

const static char* plugin_description = "EEMO DNS de-NAT data extraction plug-in " PACKAGE_VERSION;

/* DNS handler handles */
static unsigned long	dns_handler_handle	= 0;

/* Output file prefix */
static char*		out_csv_prefix		= NULL;
static FILE*		out_query_csv		= NULL;
static FILE*		out_response_csv	= NULL;
static int		is_first_file		= 1;

/* Addresses of resolver to monitor */
static struct in_addr	v4_mon;
static int		v4_mon_set		= 0;
static struct in6_addr	v6_mon;
static int		v6_mon_set		= 0;

/* Roll the output file if necessary */
static void eemo_dnsdenatex_roll_outfile(const time_t epoch)
{
	char 	csv_name_queries[256]	= { 0 };
	char 	csv_name_responses[256]	= { 0 };

	if (!is_first_file)
	{
		/* Roll on whole hours */
		if (epoch % 3600 != 0) return;
	}

	is_first_file = 0;

	if (out_query_csv != NULL)
	{
		INFO_MSG("Closing current output file for queries");

		fclose(out_query_csv);
		out_query_csv = NULL;
	}

	if (out_response_csv != NULL)
	{
		INFO_MSG("Closing current output file for responses");

		fclose(out_response_csv);
		out_response_csv = NULL;
	}

	snprintf(csv_name_queries, 256, "%s-q-%u.csv", out_csv_prefix, (unsigned int) epoch);
	snprintf(csv_name_responses, 256, "%s-r-%u.csv", out_csv_prefix, (unsigned int) epoch);

	out_query_csv = fopen(csv_name_queries, "w");
	out_response_csv = fopen(csv_name_responses, "w");

	/* Dirty, but works */
	assert(out_query_csv != NULL);
	assert(out_response_csv != NULL);

	/* Write headers */
	fprintf(out_query_csv,    "timestamp,client_ip,ip_ipid,ip_ttl,udp_srcport,dns_qid,dns_qtype,dns_qclass,dns_qname,dns_edns0,dns_edns0_do,dns_edns0_maxsize\n");
	fprintf(out_response_csv, "timestamp,client_ip,ip_ipid,ip_ttl,udp_dstport,dns_qid,dns_qtype,dns_qclass,dns_qname,first_response_ttl,dns_edns0,dns_edns0_do,dns_edns0_maxsize\n");

	INFO_MSG("Opened %s for queries", csv_name_queries);
	INFO_MSG("Opened %s for responses", csv_name_responses);
}

/* DNS handler */
eemo_rv eemo_dnsdenatex_dns_handler(eemo_ip_packet_info ip_info, int is_tcp, const eemo_dns_packet* pkt)
{
	int	dstmatch	= 0;
	int	srcmatch	= 0;

	/* Skip IPv6 traffic */
	if (ip_info.ip_type == IP_TYPE_V6) return ERV_SKIPPED;

	/* Skip TCP traffic */
	if (is_tcp) return ERV_SKIPPED;

	/* Roll files if necessary */
	eemo_dnsdenatex_roll_outfile(ip_info.ts.tv_sec);

	if (pkt->qr_flag == 0)
	{
		/* Handle queries */

		/* Check if the query was sent to the resolver we are monitoring */
		if ((ip_info.ip_type == IP_TYPE_V4) && v4_mon_set)
		{
			if (memcmp(&ip_info.dst_addr.v4, &v4_mon, sizeof(struct in_addr)) == 0)
			{
				dstmatch = 1;
			}
		}
		else if ((ip_info.ip_type == IP_TYPE_V6) && v6_mon_set)
		{
			if (memcmp(&ip_info.dst_addr.v6, &v6_mon, sizeof(struct in6_addr)) == 0)
			{
				dstmatch = 1;
			}
		}
	
		if (!dstmatch) return ERV_SKIPPED;
	
		if (pkt->questions != NULL)
		{
			fprintf(out_query_csv, "%u.%u", (unsigned int) ip_info.ts.tv_sec, (unsigned int) ip_info.ts.tv_usec);
			fprintf(out_query_csv, ",%s", ip_info.ip_src);
			fprintf(out_query_csv, ",%u", (unsigned int) ip_info.ip_id);
			fprintf(out_query_csv, ",%u", (unsigned int) ip_info.ttl);
			fprintf(out_query_csv, ",%u", (unsigned int) pkt->srcport);
			fprintf(out_query_csv, ",%u", (unsigned int) pkt->query_id);
			fprintf(out_query_csv, ",%u", (unsigned int) pkt->questions->qtype);
			fprintf(out_query_csv, ",%u", (unsigned int) pkt->questions->qclass);
			fprintf(out_query_csv, ",%s", pkt->questions->qname);
			fprintf(out_query_csv, ",%u", (unsigned int) pkt->has_edns0);
	
			if (pkt->has_edns0)
			{
				fprintf(out_query_csv, ",%d", (int) pkt->edns0_do);
				fprintf(out_query_csv, ",%u", (int) pkt->edns0_max_size);
			}
			else
			{
				fprintf(out_query_csv, ",0,0");
			}
	
			fprintf(out_query_csv, "\n");
	
			fflush(out_query_csv);
		}
		else
		{
			DEBUG_MSG("Skipped packet with empty question section");

			return ERV_SKIPPED;
		}
	}
	else
	{
		/* Handle responses */

		/* Check if the response was sent by the resolver we are monitoring */
		if ((ip_info.ip_type == IP_TYPE_V4) && v4_mon_set)
		{
			if (memcmp(&ip_info.src_addr.v4, &v4_mon, sizeof(struct in_addr)) == 0)
			{
				srcmatch = 1;
			}
		}
		else if ((ip_info.ip_type == IP_TYPE_V6) && v6_mon_set)
		{
			if (memcmp(&ip_info.src_addr.v6, &v6_mon, sizeof(struct in6_addr)) == 0)
			{
				srcmatch = 1;
			}
		}
	
		if (!srcmatch) return ERV_SKIPPED;
	
		if (pkt->questions != NULL)
		{
			fprintf(out_response_csv, "%u.%u", (unsigned int) ip_info.ts.tv_sec, (unsigned int) ip_info.ts.tv_usec);
			fprintf(out_response_csv, ",%s", ip_info.ip_dst);
			fprintf(out_response_csv, ",%u", (unsigned int) ip_info.ip_id);
			fprintf(out_response_csv, ",%u", (unsigned int) ip_info.ttl);
			fprintf(out_response_csv, ",%u", (unsigned int) pkt->dstport);
			fprintf(out_response_csv, ",%u", (unsigned int) pkt->query_id);
			fprintf(out_response_csv, ",%u", (unsigned int) pkt->questions->qtype);
			fprintf(out_response_csv, ",%u", (unsigned int) pkt->questions->qclass);
			fprintf(out_response_csv, ",%s", pkt->questions->qname);
			if (pkt->answers != NULL)
			{
				/* TTL of first record in the answer section */
				fprintf(out_response_csv, ",%u", pkt->answers->ttl);
			}
			else
			{
				fprintf(out_response_csv, ",-1");	/* no answers... */
			}
			fprintf(out_response_csv, ",%u", (unsigned int) pkt->has_edns0);
	
			if (pkt->has_edns0)
			{
				fprintf(out_response_csv, ",%d", (int) pkt->edns0_do);
				fprintf(out_response_csv, ",%u", (int) pkt->edns0_max_size);
			}
			else
			{
				fprintf(out_response_csv, ",0,0");
			}
	
			fprintf(out_response_csv, "\n");
	
			fflush(out_response_csv);
		}
		else
		{
			DEBUG_MSG("Skipped packet with empty question section");

			return ERV_SKIPPED;
		}
	}

	return ERV_HANDLED;
}

/* Plugin initialisation */
eemo_rv eemo_dnsdenatex_init(eemo_export_fn_table_ptr eemo_fn, const char* conf_base_path)
{
	char*	v4_mon_str	= NULL;
	char*	v6_mon_str	= NULL;

	/* Initialise logging for the plugin */
	eemo_init_plugin_log(eemo_fn->log);

	INFO_MSG("Initialising DNS de-NAT data extraction plugin");

	if (((eemo_fn->conf_get_string)(conf_base_path, "out_prefix", &out_csv_prefix, NULL) != ERV_OK) || (out_csv_prefix == NULL))
	{
		ERROR_MSG("Could not get output file name prefix from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if ((eemo_fn->conf_get_string)(conf_base_path, "v4_resolver", &v4_mon_str, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve the IPv4 address of the resolver to monitor from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (v4_mon_str != NULL)
	{
		if (inet_pton(AF_INET, v4_mon_str, &v4_mon) != 1)
		{
			ERROR_MSG("Failed to parse '%s' as an IPv4 address", v4_mon_str);

			return ERV_CONFIG_ERROR;
		}

		INFO_MSG("Monitoring resolver IPv4 address %s", v4_mon_str);

		free(v4_mon_str);

		v4_mon_set = 1;
	}

	if ((eemo_fn->conf_get_string)(conf_base_path, "v6_resolver", &v6_mon_str, NULL) != ERV_OK)
	{
		ERROR_MSG("Failed to retrieve the IPv6 address of the resolver to monitor from the configuration");

		return ERV_CONFIG_ERROR;
	}

	if (v6_mon_str != NULL)
	{
		if (inet_pton(AF_INET6, v6_mon_str, &v6_mon) != 1)
		{
			ERROR_MSG("Failed to parse '%s' as an IPv6 address", v6_mon_str);

			return ERV_CONFIG_ERROR;
		}

		INFO_MSG("Monitoring resolver IPv6 address %s", v6_mon_str);

		free(v6_mon_str);

		v6_mon_set = 1;
	}

	if (!v4_mon_set && !v6_mon_set)
	{
		ERROR_MSG("No resolver to monitor configured via IPv4 nor IPv6");

		return ERV_CONFIG_ERROR;
	}

	/* Register DNS handler */
	if ((eemo_fn->reg_dns_handler)(&eemo_dnsdenatex_dns_handler, PARSE_QUERY|PARSE_RESPONSE|PARSE_CANONICALIZE_NAME, &dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to register dnsdenatex DNS handler");

		(eemo_fn->unreg_dns_handler)(dns_handler_handle);

		return ERV_GENERAL_ERROR;
	}

	INFO_MSG("DNS de-NAT data extraction plugin initialisation complete");

	return ERV_OK;
}

/* Plugin uninitialisation */
eemo_rv eemo_dnsdenatex_uninit(eemo_export_fn_table_ptr eemo_fn)
{
	INFO_MSG("Uninitialising dnsdenatex plugin");

	/* Unregister DNS handler */
	if ((eemo_fn->unreg_dns_handler)(dns_handler_handle) != ERV_OK)
	{
		ERROR_MSG("Failed to unregister dnsdenatex DNS handler");
	}

	free(out_csv_prefix);

	if (out_query_csv != NULL)
	{
		fclose(out_query_csv);
		out_query_csv = NULL;
	}

	if (out_response_csv != NULL)
	{
		fclose(out_response_csv);
		out_response_csv = NULL;
	}

	INFO_MSG("Finished uninitialising dnsdenatex plugin");

	return ERV_OK;
}

/* Retrieve plugin description */
const char* eemo_dnsdenatex_getdescription(void)
{
	return plugin_description;
}

/* Retrieve plugin status */
eemo_rv eemo_dnsdenatex_status(void)
{
	return ERV_OK;
}

/* Plugin function table */
static eemo_plugin_fn_table dnsdenatex_fn_table =
{
	EEMO_PLUGIN_FN_VERSION,
	&eemo_dnsdenatex_init,
	&eemo_dnsdenatex_uninit,
	&eemo_dnsdenatex_getdescription,
	&eemo_dnsdenatex_status
};

/* Entry point for retrieving plugin function table */
eemo_rv eemo_plugin_get_fn_table(eemo_plugin_fn_table_ptrptr fn_table)
{
	if (fn_table == NULL)
	{
		return ERV_PARAM_INVALID;
	}

	*fn_table = &dnsdenatex_fn_table;

	return ERV_OK;
}

