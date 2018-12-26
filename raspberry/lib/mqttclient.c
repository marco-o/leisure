#include "mqttclient.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#ifdef HAVE_MALLOC
#include <stdlib.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>


#ifdef _MSC_VER
#define CLOCK_MONOTONIC 0
int clock_gettime(int, struct timespec *spec);     //C-file part
#endif

void mqtt_client_init(mqtt_client_t *self, const char *client_id, int clean, uint16_t keepalive)
{
	memset(self, 0, sizeof(mqtt_client_t));
	self->keepalive = keepalive;
	mqtt_connect_build(&self->clientmsg, client_id, clean, keepalive);
	self->msgid = 1;
}

void mqtt_client_credentials(mqtt_client_t *self, const char *username, const char *password, int passlen)
{
	mqtt_connect_credentials(&self->clientmsg, username, password, passlen);
}

void mqtt_client_callbacks(mqtt_client_t *self, mqtt_on_connect_t on_connect, mqtt_on_publish_t on_publish)
{
	self->on_connect = on_connect;
	self->on_publish = on_publish;
}

int mqtt_client_connected(mqtt_client_t *self)
{
    return self->socket != 0 ;
}

int mqtt_client_send(mqtt_client_t *self, mqtt_message_t *message)
{
	mqtt_packet_t packet;
	mqtt_packet_init(&packet, self->buffer, sizeof(self->buffer));
	mqtt_message_write(message, &packet);
	if (packet.head > packet.size)
    {
#ifdef HAVE_MALLOC
		if (self->prv_size < packet.head)
		{
			if (self->prv_buffer != NULL)
				free(self->prv_buffer);
			self->prv_size = packet.head * 5 / 4;
			self->prv_buffer = malloc(self->prv_size);
        }
		mqtt_packet_init(&packet, self->prv_buffer, self->prv_size);
		mqtt_message_write(message, &packet);
#else
		return packet.size;
#endif
    }
	if (self->sender && self->socket) // remote server may be down
		if (self->sender(self, packet.data, packet.head) < 0)
			return -1;

	clock_gettime(CLOCK_MONOTONIC, &self->last_send);
	return 0;
}


int mqtt_client_loop(mqtt_client_t *self, int block)
{
	int len;
	mqtt_message_t message;
	int keepalive_tout = self->keepalive * 3 / 4 ;

	for (len = 0; len < sizeof(self->buffer_in);)
	{
		if (!block || !self->avail(self, keepalive_tout))
		{
			struct timespec now ;
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (now.tv_sec - self->last_send.tv_sec > keepalive_tout - 1)
			{
				mqtt_verbose_log(self, "Sending ping\n") ;
				mqtt_pub_xxx_build(&message, PINGREQ, 0);
				if (mqtt_client_send(self, &message) < 0)
					return -1;
				continue;
			}
		}
		int read = self->recv(self, (char *)self->buffer_in + len, sizeof(self->buffer_in) - len) ;
		if (read > 0)
		{
			int msg_len;
			mqtt_packet_t packet;
			len += read;
			mqtt_packet_init(&packet, self->buffer_in, len);
			while ((msg_len = mqtt_message_peek(&message, &packet)) <= len)
			{
				mqtt_message_read(&message, &packet);
				switch (message.header.ctrl >> 4)
				{
				case PUBLISH:
					if ((message.header.ctrl & 0x06) == 0x02) /* QoS = 1 */
					{
						mqtt_message_t reply;
						mqtt_pub_xxx_build(&reply, PUBACK, message.variable.publish.packetid);
						if (mqtt_client_send(self, &reply) < 0)
						    return -1 ;
					}
					if (self->on_publish)
						self->on_publish(self, &message.variable.publish.topic, &message.payload.publish);
					break;
				case CONNECT:
					mqtt_verbose_log(self, "CONNECT!");
					mqtt_pub_xxx_build(&message, CONNACK, 0);
					if (mqtt_client_send(self, &message) < 0)
					    return -1 ;
					break;
				case CONNACK:
					if (self->on_connect && message.variable.connack.byte2 == 0)
						self->on_connect(self);
					break;
				default:
					break;
				}
				len -= msg_len;
				if (len > 0)
				{
					memmove(self->buffer_in, self->buffer_in + msg_len, len);
					mqtt_packet_init(&packet, self->buffer_in, len);
				}
				if (!block && len == 0)
					return 0;
			}
		}
		else if (read < 0)
		{
			if (block)
				mqtt_verbose_log(self, "recv failed, exiting loop (len=%d, req = %d)\n",
					len, sizeof(self->buffer_in) - len);
			return -1;
		}
		else if (!block)
			return 0;
	}
	return 0;
}

void mqtt_client_shutdown(mqtt_client_t *self)
{
	if (self->socket)
	{
		mqtt_message_t message;
		mqtt_disconnect_build(&message);
		mqtt_client_send(self, &message);
#ifdef HAVE_MALLOC
		if (self->prv_buffer != NULL)
			free(self->prv_buffer);
#endif
		self->shut(self);
	}
}
