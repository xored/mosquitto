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

#include <cjson/cJSON.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "json_help.h"
#include "mosquitto.h"
#include "mosquitto_broker.h"
#include "mosquitto_plugin.h"
#include "mqtt_protocol.h"

#include "dynamic_security.h"

void dynsec__command_reply(cJSON *j_responses, struct mosquitto *context, const char *command, const char *error, const char *correlation_data)
{
	cJSON *j_response;

	UNUSED(context);

	j_response = cJSON_CreateObject();
	if(j_response == NULL) return;

	if(cJSON_AddStringToObject(j_response, "command", command) == NULL
			|| (error && cJSON_AddStringToObject(j_response, "error", error) == NULL)
			|| (correlation_data && cJSON_AddStringToObject(j_response, "correlationData", correlation_data) == NULL)
			){

		cJSON_Delete(j_response);
		return;
	}

	cJSON_AddItemToArray(j_responses, j_response);
}


static void send_response(cJSON *tree)
{
	char *payload;
	size_t payload_len;

	payload = cJSON_PrintUnformatted(tree);
	cJSON_Delete(tree);
	if(payload == NULL) return;

	payload_len = strlen(payload);
	if(payload_len > MQTT_MAX_PAYLOAD){
		free(payload);
		return;
	}
	mosquitto_broker_publish(NULL, "$CONTROL/dynamic-security/v1/response",
			(int)payload_len, payload, 0, 0, NULL);
}


int dynsec_control_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_control *ed = event_data;
	cJSON *tree, *commands;
	cJSON *j_response_tree, *j_responses;

	UNUSED(event);
	UNUSED(userdata);

	/* Create object for responses */
	j_response_tree = cJSON_CreateObject();
	if(j_response_tree == NULL){
		return MOSQ_ERR_NOMEM;
	}
	j_responses = cJSON_CreateArray();
	if(j_responses == NULL){
		cJSON_Delete(j_response_tree);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(j_response_tree, "responses", j_responses);


	/* Parse cJSON tree.
	 * Using cJSON_ParseWithLength() is the best choice here, but Mosquitto
	 * always adds an extra 0 to the end of the payload memory, so using
	 * cJSON_Parse() on its own will still not overrun. */
#if CJSON_VERSION_FULL < 1007013
	tree = cJSON_Parse(ed->payload);
#else
	tree = cJSON_ParseWithLength(ed->payload, ed->payloadlen);
#endif
	if(tree == NULL){
		dynsec__command_reply(j_responses, ed->client, "Unknown command", "Payload not valid JSON", NULL);
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}
	commands = cJSON_GetObjectItem(tree, "commands");
	if(commands == NULL || !cJSON_IsArray(commands)){
		cJSON_Delete(tree);
		dynsec__command_reply(j_responses, ed->client, "Unknown command", "Invalid/missing commands", NULL);
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}

	/* Handle commands */
	dynsec__handle_control(j_responses, ed->client, commands);
	cJSON_Delete(tree);

	send_response(j_response_tree);

	return MOSQ_ERR_SUCCESS;
}


/* ################################################################
 * #
 * # $CONTROL/dynamic-security/v1 handler
 * #
 * ################################################################ */

int dynsec__handle_control(cJSON *j_responses, struct mosquitto *context, cJSON *commands)
{
	int rc = MOSQ_ERR_SUCCESS;
	cJSON *aiter;
	char *command;
	char *correlation_data = NULL;

	cJSON_ArrayForEach(aiter, commands){
		if(cJSON_IsObject(aiter)){
			if(json_get_string(aiter, "command", &command, false) == MOSQ_ERR_SUCCESS){
				if(json_get_string(aiter, "correlationData", &correlation_data, true) != MOSQ_ERR_SUCCESS){
					dynsec__command_reply(j_responses, context, command, "Invalid correlationData data type.", NULL);
					return MOSQ_ERR_INVAL;
				}

				/* Plugin */
				if(!strcasecmp(command, "setDefaultACLAccess")){
					rc = dynsec__process_set_default_acl_access(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getDefaultACLAccess")){
					rc = dynsec__process_get_default_acl_access(j_responses, context, aiter, correlation_data);

				/* Clients */
				}else if(!strcasecmp(command, "createClient")){
					rc = dynsec_clients__process_create(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "deleteClient")){
					rc = dynsec_clients__process_delete(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getClient")){
					rc = dynsec_clients__process_get(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "listClients")){
					rc = dynsec_clients__process_list(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "modifyClient")){
					rc = dynsec_clients__process_modify(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "setClientPassword")){
					rc = dynsec_clients__process_set_password(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "setClientId")){
					rc = dynsec_clients__process_set_id(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "addClientRole")){
					rc = dynsec_clients__process_add_role(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeClientRole")){
					rc = dynsec_clients__process_remove_role(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "enableClient")){
					rc = dynsec_clients__process_enable(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "disableClient")){
					rc = dynsec_clients__process_disable(j_responses, context, aiter, correlation_data);

				/* Groups */
				}else if(!strcasecmp(command, "addGroupClient")){
					rc = dynsec_groups__process_add_client(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "createGroup")){
					rc = dynsec_groups__process_create(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "deleteGroup")){
					rc = dynsec_groups__process_delete(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getGroup")){
					rc = dynsec_groups__process_get(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "listGroups")){
					rc = dynsec_groups__process_list(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "modifyGroup")){
					rc = dynsec_groups__process_modify(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeGroupClient")){
					rc = dynsec_groups__process_remove_client(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "addGroupRole")){
					rc = dynsec_groups__process_add_role(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeGroupRole")){
					rc = dynsec_groups__process_remove_role(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "setAnonymousGroup")){
					rc = dynsec_groups__process_set_anonymous_group(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getAnonymousGroup")){
					rc = dynsec_groups__process_get_anonymous_group(j_responses, context, aiter, correlation_data);

				/* Roles */
				}else if(!strcasecmp(command, "createRole")){
					rc = dynsec_roles__process_create(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "getRole")){
					rc = dynsec_roles__process_get(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "listRoles")){
					rc = dynsec_roles__process_list(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "modifyRole")){
					rc = dynsec_roles__process_modify(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "deleteRole")){
					rc = dynsec_roles__process_delete(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "addRoleACL")){
					rc = dynsec_roles__process_add_acl(j_responses, context, aiter, correlation_data);
				}else if(!strcasecmp(command, "removeRoleACL")){
					rc = dynsec_roles__process_remove_acl(j_responses, context, aiter, correlation_data);

				/* Unknown */
				}else{
					dynsec__command_reply(j_responses, context, command, "Unknown command", correlation_data);
					rc = MOSQ_ERR_INVAL;
				}
			}else{
				dynsec__command_reply(j_responses, context, "Unknown command", "Missing command", correlation_data);
				rc = MOSQ_ERR_INVAL;
			}
		}else{
			dynsec__command_reply(j_responses, context, "Unknown command", "Command not an object", correlation_data);
			rc = MOSQ_ERR_INVAL;
		}
	}

	return rc;
}
