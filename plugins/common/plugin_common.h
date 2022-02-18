#ifndef PLUGIN_SHARED_H
#define PLUGIN_SHARED_H

#include <cjson/cJSON.h>

struct plugin_cmd{
	cJSON *j_responses;
	cJSON *j_command;
	char *correlation_data;
	const char *command_name;
};

void plugin__command_reply(struct plugin_cmd *cmd, const char *error);

void plugin_send_response(cJSON *tree, const char* topic);

#endif
