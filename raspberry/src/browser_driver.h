#ifndef browser_driverH
#define browser_driverH

#include <stdint.h>
#include <time.h>
#include "mqttclient.h"
#include "cJSON.h"

#define MQTT_TIMEOUT_SEC    300
#define MQTT_RECONNECT_SECS 600

#define MAX_NAME_LEN 64

#define HAVE_X


typedef struct browser_driver_s browser_driver_t ;
typedef struct mqtt_client_item_s mqtt_client_item_t;
struct mqtt_client_item_s 
{
	mqtt_client_t       client; // connection to broker
	mqtt_message_t      message;
	char                prefix[MAX_NAME_LEN];
	char                host[MAX_NAME_LEN];
	char                port[MAX_NAME_LEN];
	struct timespec     downat;  // used to attemt a reconnect after a given time
	                             // when zero means connection is successfull
	browser_driver_t   *master;
	mqtt_client_item_t *next;
} ;

struct browser_driver_s
{
	char               stop ; 
	mqtt_client_item_t *clients;
	//config_t            config;
#ifdef HAVE_X
        void                *display ;
#endif
	char                hw_id[MAX_NAME_LEN];
}  ;

int  browser_driver_init(browser_driver_t *, const char *config, const char *hw_id);
int  browser_driver_connect(browser_driver_t *, const char *host, const char *port);
void browser_driver_loop(browser_driver_t *);
void browser_driver_shut(browser_driver_t *);


#endif