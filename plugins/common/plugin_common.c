#include "plugin_common.h"
#include <mqtt_protocol.h>
#include <mosquitto_broker.h>

#include <stdlib.h>
#include <string.h>

void plugin__command_reply(struct plugin_cmd *cmd, const char *error)
{
	cJSON *j_response;

	j_response = cJSON_CreateObject();
	if(j_response == NULL) return;

	if(cJSON_AddStringToObject(j_response, "command", cmd->command_name) == NULL
			|| (error && cJSON_AddStringToObject(j_response, "error", error) == NULL)
			|| (cmd->correlation_data && cJSON_AddStringToObject(j_response, "correlationData", cmd->correlation_data) == NULL)
			){

		cJSON_Delete(j_response);
		return;
	}

	cJSON_AddItemToArray(cmd->j_responses, j_response);
}

void plugin_send_response(cJSON *tree, const char* topic)
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
	mosquitto_broker_publish(NULL, topic, (int)payload_len, payload, 0, 0, NULL);
}

