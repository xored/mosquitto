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

static void send_response(cJSON *tree)
{
	plugin_send_response(tree, "$CONTROL/dynamic-security/v1/response");
}


int dynsec_control_callback(int event, void *event_data, void *userdata)
{
	struct mosquitto_evt_control *ed = event_data;
	struct dynsec__data *data = userdata;
	struct plugin_cmd cmd;
	cJSON *tree, *commands;
	cJSON *j_response_tree;

	UNUSED(event);
	UNUSED(userdata);

	memset(&cmd, 0, sizeof(cmd));
	cmd.command_name = "Unknown command";

	/* Create object for responses */
	j_response_tree = cJSON_CreateObject();
	if(j_response_tree == NULL){
		return MOSQ_ERR_NOMEM;
	}
	cmd.j_responses = cJSON_AddArrayToObject(j_response_tree, "responses");
	if(cmd.j_responses == NULL){
		cJSON_Delete(j_response_tree);
		return MOSQ_ERR_NOMEM;
	}

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
		plugin__command_reply(&cmd, "Payload not valid JSON");
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}
	commands = cJSON_GetObjectItem(tree, "commands");
	if(commands == NULL || !cJSON_IsArray(commands)){
		cJSON_Delete(tree);
		plugin__command_reply(&cmd, "Invalid/missing commands");
		send_response(j_response_tree);
		return MOSQ_ERR_SUCCESS;
	}

	/* Handle commands */
	dynsec__handle_control(data, &cmd, ed->client, commands);
	cJSON_Delete(tree);

	send_response(j_response_tree);

	return MOSQ_ERR_SUCCESS;
}


/* ################################################################
 * #
 * # $CONTROL/dynamic-security/v1 handler
 * #
 * ################################################################ */

int dynsec__handle_control(struct dynsec__data *data, struct plugin_cmd *cmd, struct mosquitto *context, cJSON *commands)
{
	int rc = MOSQ_ERR_SUCCESS;
	cJSON *aiter;
	char *command;

	cJSON_ArrayForEach(aiter, commands){
		cmd->command_name = "Unknown command";
		if(cJSON_IsObject(aiter)){
			if(json_get_string(aiter, "command", &command, false) == MOSQ_ERR_SUCCESS){
				cmd->j_command = aiter;
				cmd->correlation_data = NULL;
				cmd->command_name = command;

				if(json_get_string(aiter, "correlationData", &cmd->correlation_data, true) != MOSQ_ERR_SUCCESS){
					plugin__command_reply(cmd, "Invalid correlationData data type.");
					return MOSQ_ERR_INVAL;
				}

				/* Plugin */
				if(!strcasecmp(command, "setDefaultACLAccess")){
					rc = dynsec__process_set_default_acl_access(data, cmd, context);
				}else if(!strcasecmp(command, "getDefaultACLAccess")){
					rc = dynsec__process_get_default_acl_access(data, cmd, context);

				/* Clients */
				}else if(!strcasecmp(command, "createClient")){
					rc = dynsec_clients__process_create(data, cmd, context);
				}else if(!strcasecmp(command, "deleteClient")){
					rc = dynsec_clients__process_delete(data, cmd, context);
				}else if(!strcasecmp(command, "getClient")){
					rc = dynsec_clients__process_get(data, cmd, context);
				}else if(!strcasecmp(command, "listClients")){
					rc = dynsec_clients__process_list(data, cmd, context);
				}else if(!strcasecmp(command, "modifyClient")){
					rc = dynsec_clients__process_modify(data, cmd, context);
				}else if(!strcasecmp(command, "setClientPassword")){
					rc = dynsec_clients__process_set_password(data, cmd, context);
				}else if(!strcasecmp(command, "setClientId")){
					rc = dynsec_clients__process_set_id(data, cmd, context);
				}else if(!strcasecmp(command, "addClientRole")){
					rc = dynsec_clients__process_add_role(data, cmd, context);
				}else if(!strcasecmp(command, "removeClientRole")){
					rc = dynsec_clients__process_remove_role(data, cmd, context);
				}else if(!strcasecmp(command, "enableClient")){
					rc = dynsec_clients__process_enable(data, cmd, context);
				}else if(!strcasecmp(command, "disableClient")){
					rc = dynsec_clients__process_disable(data, cmd, context);

				/* Groups */
				}else if(!strcasecmp(command, "addGroupClient")){
					rc = dynsec_groups__process_add_client(data, cmd, context);
				}else if(!strcasecmp(command, "createGroup")){
					rc = dynsec_groups__process_create(data, cmd, context);
				}else if(!strcasecmp(command, "deleteGroup")){
					rc = dynsec_groups__process_delete(data, cmd, context);
				}else if(!strcasecmp(command, "getGroup")){
					rc = dynsec_groups__process_get(data, cmd, context);
				}else if(!strcasecmp(command, "listGroups")){
					rc = dynsec_groups__process_list(data, cmd, context);
				}else if(!strcasecmp(command, "modifyGroup")){
					rc = dynsec_groups__process_modify(data, cmd, context);
				}else if(!strcasecmp(command, "removeGroupClient")){
					rc = dynsec_groups__process_remove_client(data, cmd, context);
				}else if(!strcasecmp(command, "addGroupRole")){
					rc = dynsec_groups__process_add_role(data, cmd, context);
				}else if(!strcasecmp(command, "removeGroupRole")){
					rc = dynsec_groups__process_remove_role(data, cmd, context);
				}else if(!strcasecmp(command, "setAnonymousGroup")){
					rc = dynsec_groups__process_set_anonymous_group(data, cmd, context);
				}else if(!strcasecmp(command, "getAnonymousGroup")){
					rc = dynsec_groups__process_get_anonymous_group(data, cmd, context);

				/* Roles */
				}else if(!strcasecmp(command, "createRole")){
					rc = dynsec_roles__process_create(data, cmd, context);
				}else if(!strcasecmp(command, "getRole")){
					rc = dynsec_roles__process_get(data, cmd, context);
				}else if(!strcasecmp(command, "listRoles")){
					rc = dynsec_roles__process_list(data, cmd, context);
				}else if(!strcasecmp(command, "modifyRole")){
					rc = dynsec_roles__process_modify(data, cmd, context);
				}else if(!strcasecmp(command, "deleteRole")){
					rc = dynsec_roles__process_delete(data, cmd, context);
				}else if(!strcasecmp(command, "addRoleACL")){
					rc = dynsec_roles__process_add_acl(data, cmd, context);
				}else if(!strcasecmp(command, "removeRoleACL")){
					rc = dynsec_roles__process_remove_acl(data, cmd, context);

				/* Unknown */
				}else{
					plugin__command_reply(cmd, "Unknown command");
					rc = MOSQ_ERR_INVAL;
				}
			}else{
				plugin__command_reply(cmd, "Missing command");
				rc = MOSQ_ERR_INVAL;
			}
		}else{
			plugin__command_reply(cmd, "Command not an object");
			rc = MOSQ_ERR_INVAL;
		}
	}

	return rc;
}
