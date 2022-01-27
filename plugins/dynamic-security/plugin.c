/*
Copyright (c) 2020-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mqtt_protocol.h"

#include "dynamic_security.h"

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

struct dynsec__data g_dynsec_data;
static mosquitto_plugin_id_t *plg_id = NULL;
char *g_config_file = NULL;

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data, struct mosquitto_opt *options, int option_count)
{
	int i;

	UNUSED(user_data);

	memset(&g_dynsec_data, 0, sizeof(struct dynsec__data));

	for(i=0; i<option_count; i++){
		if(!strcasecmp(options[i].key, "config_file")){
			g_config_file = mosquitto_strdup(options[i].value);
			if(g_config_file == NULL){
				return MOSQ_ERR_NOMEM;
			}
			break;
		}
	}
	if(g_config_file == NULL){
		mosquitto_log_printf(MOSQ_LOG_WARNING, "Warning: Dynamic security plugin has no plugin_opt_config_file defined. The plugin will not be activated.");
		return MOSQ_ERR_SUCCESS;
	}

	plg_id = identifier;
	mosquitto_plugin_set_info(identifier, "dynamic-security", NULL);

	dynsec__config_load();
	mosquitto_callback_register(plg_id, MOSQ_EVT_CONTROL, dynsec_control_callback, "$CONTROL/dynamic-security/v1", NULL);
	mosquitto_callback_register(plg_id, MOSQ_EVT_BASIC_AUTH, dynsec_auth__basic_auth_callback, NULL, NULL);
	mosquitto_callback_register(plg_id, MOSQ_EVT_ACL_CHECK, dynsec__acl_check_callback, NULL, NULL);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *options, int option_count)
{
	UNUSED(user_data);
	UNUSED(options);
	UNUSED(option_count);

	dynsec_groups__cleanup();
	dynsec_clients__cleanup();
	dynsec_roles__cleanup();

	mosquitto_free(g_config_file);
	g_config_file = NULL;
	return MOSQ_ERR_SUCCESS;
}
