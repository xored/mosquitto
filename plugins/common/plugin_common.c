#include <cjson/cJSON.h>
#include "plugin_common.h"

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
