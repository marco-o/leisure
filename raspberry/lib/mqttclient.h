#ifndef mqttclientH
#define mqttclientH

#include <time.h>
#include "mqttparser.h"

/* Definition of a few message handlers */
typedef struct mqtt_client_s mqtt_client_t;
typedef void(*mqtt_on_connect_t)(mqtt_client_t *);
typedef void(*mqtt_on_publish_t)(mqtt_client_t *, const mqtt_text_t *topic, const mqtt_text_t *message);

/* Data transmission related functions */
typedef int  (*mqtt_sender_t)(mqtt_client_t *, void *, int) ; // data sender
typedef int  (*mqtt_avail_t) (mqtt_client_t *, int) ;         // test for data available
typedef int  (*mqtt_recv_t)(mqtt_client_t *, void *, int) ;        // data receiver
typedef void (*mqtt_close_t)(mqtt_client_t *) ;

#define BUFFER_SIZE 512
#define HAVE_MALLOC

struct mqtt_client_s
{
	long              socket;
	void             *sock_data;
	mqtt_sender_t     sender;
	mqtt_avail_t      avail;
	mqtt_recv_t       recv;
	mqtt_close_t      shut;
	uint16_t          msgid;
	uint8_t           buffer[BUFFER_SIZE];
#ifdef HAVE_MALLOC
	uint8_t           *prv_buffer;
	int               prv_size;
#endif
	uint8_t           buffer_in[BUFFER_SIZE];
	int               keepalive;
	void             *data ;	
	struct timespec    last_send ;	// last time something was sent (for keepalive purposes)
	mqtt_message_t    clientmsg;
	mqtt_on_connect_t on_connect;
	mqtt_on_publish_t on_publish;
} ;

void mqtt_client_init(mqtt_client_t *self, const char *client_id, int clean, uint16_t keepalive) ;
void mqtt_client_credentials(mqtt_client_t *, const char *username, const char *password, int passlen) ;
void mqtt_client_callbacks(mqtt_client_t *, mqtt_on_connect_t on_connect, mqtt_on_publish_t on_publish) ;
int  mqtt_client_transport_init(mqtt_client_t *, const char *, const char *) ;
int  mqtt_client_connected(mqtt_client_t *self) ;
int  mqtt_client_send(mqtt_client_t *self, mqtt_message_t *message) ;
int  mqtt_client_loop(mqtt_client_t *self, int block);
void mqtt_client_shutdown(mqtt_client_t *self) ;
/* this one is implemented next to main() */
void mqtt_verbose_log(mqtt_client_t *self, const char *, ...);



#endif
