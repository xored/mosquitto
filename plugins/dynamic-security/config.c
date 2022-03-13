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

static int dynsec__general_config_load(struct dynsec__data *data, cJSON *tree)
{
	cJSON *j_default_access, *jtmp;

	j_default_access = cJSON_GetObjectItem(tree, "defaultACLAccess");
	if(j_default_access && cJSON_IsObject(j_default_access)){
		jtmp = cJSON_GetObjectItem(j_default_access, ACL_TYPE_PUB_C_SEND);
		if(jtmp && cJSON_IsBool(jtmp)){
			data->default_access.publish_c_send = cJSON_IsTrue(jtmp);
		}else{
			data->default_access.publish_c_send = false;
		}

		jtmp = cJSON_GetObjectItem(j_default_access, ACL_TYPE_PUB_C_RECV);
		if(jtmp && cJSON_IsBool(jtmp)){
			data->default_access.publish_c_recv = cJSON_IsTrue(jtmp);
		}else{
			data->default_access.publish_c_recv = false;
		}

		jtmp = cJSON_GetObjectItem(j_default_access, ACL_TYPE_SUB_GENERIC);
		if(jtmp && cJSON_IsBool(jtmp)){
			data->default_access.subscribe = cJSON_IsTrue(jtmp);
		}else{
			data->default_access.subscribe = false;
		}

		jtmp = cJSON_GetObjectItem(j_default_access, ACL_TYPE_UNSUB_GENERIC);
		if(jtmp && cJSON_IsBool(jtmp)){
			data->default_access.unsubscribe = cJSON_IsTrue(jtmp);
		}else{
			data->default_access.unsubscribe = false;
		}
	}
	return MOSQ_ERR_SUCCESS;
}

static int dynsec__general_config_save(struct dynsec__data *data, cJSON *tree)
{
	cJSON *j_default_access;

	j_default_access = cJSON_CreateObject();
	if(j_default_access == NULL){
		return 1;
	}
	cJSON_AddItemToObject(tree, "defaultACLAccess", j_default_access);

	if(cJSON_AddBoolToObject(j_default_access, ACL_TYPE_PUB_C_SEND, data->default_access.publish_c_send) == NULL
			|| cJSON_AddBoolToObject(j_default_access, ACL_TYPE_PUB_C_RECV, data->default_access.publish_c_recv) == NULL
			|| cJSON_AddBoolToObject(j_default_access, ACL_TYPE_SUB_GENERIC, data->default_access.subscribe) == NULL
			|| cJSON_AddBoolToObject(j_default_access, ACL_TYPE_UNSUB_GENERIC, data->default_access.unsubscribe) == NULL
			){

		return 1;
	}

	return MOSQ_ERR_SUCCESS;
}

int dynsec__config_from_json(struct dynsec__data *data, const char *json_str)
{
	cJSON *tree;

	tree = cJSON_Parse(json_str);
	if(tree == NULL){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: File is not valid JSON.\n");
		return 1;
	}

	if(dynsec__general_config_load(data, tree)
			|| dynsec_roles__config_load(data, tree)
			|| dynsec_clients__config_load(data, tree)
			|| dynsec_groups__config_load(data, tree)
			){

		cJSON_Delete(tree);
		return 1;
	}

	cJSON_Delete(tree);
	return 0;
}

int dynsec__config_load(struct dynsec__data *data)
{
	FILE *fptr;
	long flen_l;
	size_t flen;
	char *json_str;
	int rc;

	/* Load from file */
	fptr = fopen(data->config_file, "rb");
	if(fptr == NULL){
		/* Attempt to initialise a new config file */
		if(dynsec__config_init(data->config_file) == MOSQ_ERR_SUCCESS){
			mosquitto_log_printf(MOSQ_LOG_INFO, "Dynamic security plugin config not found, generating a default config.");
			mosquitto_log_printf(MOSQ_LOG_INFO, "  Generated passwords are at %s.pw", data->config_file);
			/* If it works, try to open the file again */
			fptr = fopen(data->config_file, "rb");
		}

		if(fptr == NULL){
			mosquitto_log_printf(MOSQ_LOG_ERR,
					"Error loading Dynamic security plugin config: File is not readable - check permissions.");
			return MOSQ_ERR_UNKNOWN;
		}
	}

	fseek(fptr, 0, SEEK_END);
	flen_l = ftell(fptr);
	if(flen_l < 0){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error loading Dynamic security plugin config: %s", strerror(errno));
		fclose(fptr);
		return 1;
	}else if(flen_l == 0){
		fclose(fptr);
		return 0;
	}
	flen = (size_t)flen_l;
	fseek(fptr, 0, SEEK_SET);
	json_str = mosquitto_calloc(flen+1, sizeof(char));
	if(json_str == NULL){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Out of memory.");
		fclose(fptr);
		return 1;
	}
	if(fread(json_str, 1, flen, fptr) != flen){
		mosquitto_log_printf(MOSQ_LOG_WARNING, "Error loading Dynamic security plugin config: Unable to read file contents.\n");
		mosquitto_free(json_str);
		fclose(fptr);
		return 1;
	}
	fclose(fptr);

	rc = dynsec__config_from_json(data, json_str);
	free(json_str);
	return rc;
}

char *dynsec__config_to_json(struct dynsec__data *data)
{
	cJSON *tree;
	char *json_str;

	tree = cJSON_CreateObject();
	if(tree == NULL) return NULL;

	if(dynsec__general_config_save(data, tree)
			|| dynsec_clients__config_save(data, tree)
			|| dynsec_groups__config_save(data, tree)
			|| dynsec_roles__config_save(data, tree)){

		cJSON_Delete(tree);
		return NULL;
	}

	/* Print json to string */
	json_str = cJSON_Print(tree);
	cJSON_Delete(tree);
	return json_str;
}

void dynsec__config_save(struct dynsec__data *data)
{
	size_t file_path_len;
	char *file_path;
	FILE *fptr;
	size_t json_str_len;
	char *json_str;

	json_str = dynsec__config_to_json(data);
	if(json_str == NULL){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: Out of memory.\n");
		return;
	}
	json_str_len = strlen(json_str);

	/* Save to file */
	file_path_len = strlen(data->config_file) + 1;
	file_path = mosquitto_malloc(file_path_len);
	if(file_path == NULL){
		mosquitto_free(json_str);
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: Out of memory.\n");
		return;
	}
	snprintf(file_path, file_path_len, "%s.new", data->config_file);

	fptr = fopen(file_path, "wt");
	if(fptr == NULL){
		mosquitto_free(json_str);
		mosquitto_free(file_path);
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error saving Dynamic security plugin config: File is not writable - check permissions.\n");
		return;
	}
	fwrite(json_str, 1, json_str_len, fptr);
	mosquitto_free(json_str);
	fclose(fptr);

	/* Everything is ok, so move new file over proper file */
	if(rename(file_path, data->config_file) < 0){
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error updating dynsec config file: %s", strerror(errno));
	}
	mosquitto_free(file_path);
}
