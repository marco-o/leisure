#include "browser_driver.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


void browser_driver_message_handler(mqtt_client_t *client, const mqtt_text_t *topic, const mqtt_text_t *message) ;

// lhs - rhs, positive if first is more recent
static int timespec_diff(struct timespec *lhs, struct timespec *rhs)
{
	int res = lhs->tv_nsec - rhs->tv_nsec;
	res /= 500 * 1000 * 1000; // rounding
	res += (int)(lhs->tv_sec - rhs->tv_sec);
	return res;
}


static void browser_driver_now(browser_driver_t *self, struct timespec *ts)
{
    clock_gettime( CLOCK_MONOTONIC, ts) ; // return  -1 on failure
}

static void mqtt_build_topic(mqtt_client_item_t *item, char *buffer, const char *subtopic)
{
	buffer[0] = '\0';
	if (item->prefix != NULL && item->prefix[0] != '\0')
	{
		strcpy(buffer, item->prefix);
		strcat(buffer, "/");
	}
	strcat(buffer, subtopic);
}

static void browser_driver_client_shut(browser_driver_t *self, mqtt_client_item_t *iter)
{
	browser_driver_now(self, &iter->downat);
	mqtt_client_shutdown(&iter->client);
	mqtt_verbose_log(&iter->client, "Client shut down\n");
}

/*
 * Executed on connection accepted.
 * Subscribes to incoming messages
 */
static void mqtt_on_connect(mqtt_client_t *client)
{
	char topic[MAX_NAME_LEN];
	mqtt_message_t message;

	mqtt_build_topic((mqtt_client_item_t *)(client->data), topic, "ctrl/+");
	mqtt_subscribe_build(&message, &client->msgid, topic, 1); // used to receive commands on device side
	mqtt_client_send(client, &message);
	mqtt_verbose_log(client, "MQTT connection done!\n");
}

static int mqtt_connect(mqtt_client_t *client, void *data, const char *host, const char *port)
{
	const char *pass = "DevelUsr";
	char clientid[16];
	struct timespec ts;
	int tout = MQTT_TIMEOUT_SEC;

	if (atoi(port) > 8000)
		tout = 60; // otherwise SSL connection gets closed
	clock_gettime(CLOCK_MONOTONIC, &ts);
	sprintf(clientid, "brw-driver-%d", (int)(ts.tv_sec + ts.tv_nsec) % 1000000);
	mqtt_client_init(client, clientid, 1, tout);
	mqtt_client_credentials(client, "develusr", pass, strlen(pass));
	mqtt_client_callbacks(client, &mqtt_on_connect, &browser_driver_message_handler);
	client->data = data ;
	if (mqtt_client_transport_init(client, host, port) < 0)
		return -1;
	return 0;
}

int browser_driver_init(browser_driver_t *self, const char *config, const char *hw_id)
{
	memset(self, 0, sizeof(browser_driver_t));
//	self->file = config;
//	config_init(&self->config, browser_driver_load_config_prv(self));
	strncpy(self->hw_id, hw_id, MAX_NAME_LEN - 1);
	return 0 ;
}

int browser_driver_connect(browser_driver_t *self, const char *host, const char *port)
{
	mqtt_client_item_t *temp = malloc(sizeof(mqtt_client_item_t));
	memset(temp, 0, sizeof(mqtt_client_item_t));
	temp->next = self->clients ;
	temp->master = self;
	if (self->clients != NULL) // prefix used only on remote connections (the one after the first)
		strncpy(temp->prefix, self->hw_id, MAX_NAME_LEN - 1);
	strncpy(temp->host, host, MAX_NAME_LEN - 1);
	strncpy(temp->port, port, MAX_NAME_LEN - 1);
	self->clients = temp; // puts the client in the list anyway. It will attempt reconnection later
	if (mqtt_connect(&temp->client, temp, host, port) < 0)
	{
		browser_driver_now(self, &temp->downat);
		mqtt_verbose_log(&temp->client, "MQTT connect failed\n");
		return -1;
	}
	mqtt_client_send(&temp->client, &temp->client.clientmsg);
	return 0;
}

void browser_driver_loop(browser_driver_t *self)
{
	mqtt_client_item_t *iter = self->clients;
	for (; iter; iter = iter->next)
		if (iter->downat.tv_sec != 0)
		{
			struct timespec now;
			browser_driver_now(self, &now);
			int delta = timespec_diff(&now, &iter->downat);
			if (delta > MQTT_RECONNECT_SECS) // attempt reconnection
				if (mqtt_connect(&iter->client, iter, iter->host, iter->port) < 0)
					browser_driver_now(self, &iter->downat);
				else
				{
					mqtt_verbose_log(&iter->client, "Attempting reconnection\n");
					if (mqtt_client_send(&iter->client, &iter->client.clientmsg) == 0)
					{
						mqtt_verbose_log(&iter->client, "Client reconnected\n");
						memset(&iter->downat, 0, sizeof(struct timespec));
					}
				}

		}
		else if (mqtt_client_loop(&iter->client, 0) < 0)
		    browser_driver_client_shut(self, iter) ;
}


void browser_driver_shut(browser_driver_t *self)
{
	while (self->clients)
	{
		mqtt_client_item_t *temp = self->clients;
		self->clients = temp->next;
		mqtt_client_shutdown(&temp->client);
		free(temp);
	}
//	config_shut(&self->config);
}


void browser_driver_message_handler(mqtt_client_t *client, const mqtt_text_t *topic, const mqtt_text_t *message)
{
	cJSON *json = cJSON_Parse((char *)message->text);
	browser_driver_t *self = ((mqtt_client_item_t *)client->data)->master;

	mqtt_verbose_log(client, "Message: topic = %.*s\n", topic->length, topic->text) ;
	if (json == 0)
		return;

	char *topic_tail = (char *)topic->text; // get leaf topic
	for (char *iter = topic_tail; *iter; ++iter)
		if (*iter == '/')
			topic_tail = iter + 1;
#if 0
	if (strncmp(topic_tail, "stop", 4) == 0) // stop scene
	{
		cJSON *id = cJSON_GetObjectItem(json, "id");
		if (id != NULL)
			scene_engine_toggle(&self->scene, self, id->valueint, scene_stop_e);
	}
#ifndef _MSC_VER
	else if (strncmp(topic_tail, "wifi", 4) == 0)
    {
        dmx_connect_local_wifi(json) ;
    }
#endif
	else if (strncmp(topic_tail, "listwifi", 8) == 0)
	{
		dmx_list_local_wifi(self, json);
	}
#endif
	cJSON_Delete(json);
}