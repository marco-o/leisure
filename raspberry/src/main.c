#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#ifdef _MSC_VER
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <crtdbg.h>
#include <conio.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#endif
#include <signal.h>
#ifdef __arm__
#define HAVE_WATCHDOG
#endif

//#define HAVE_OPENSSL

#ifdef HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#ifdef _MSC_VER
#include <openssl/applink.c> // has to do with OpenSSL version?
#endif
#endif
#ifdef HAVE_WATCHDOG
#include <sys/ioctl.h>
#include <linux/watchdog.h>
#endif
#include "browser_driver.h"


int verbose = 0;
char *log_file = NULL;

void mqtt_verbose_log(mqtt_client_t *self, const char *format, ...)
{
	static FILE *lf = NULL ;
	static int count = 0;
	va_list ap;
	(void)self;
	va_start(ap, format);
	if (verbose)
	{
		FILE *log = stdout;
		if (log_file != NULL)
		{
			if (count > 2 && lf != NULL)
			{
				fclose(lf); // so we can examine output
				lf = NULL;
				count = 0;
			}
			if (lf == NULL)
				lf = fopen(log_file, "a+");
			if (lf != NULL)
				log = lf;
		}
		count++;
		vfprintf(log, format, ap);
	}
	va_end(ap);
}

#ifdef _MSC_VER
void usleep(int usecs)
{
	Sleep(usecs / 1000);
}

void sleep(int secs)
{
	usleep(secs * 1000000);
}
#endif

void log_buffer(mqtt_client_t *self, const char *msg, const void *data, int length)
{
	char buffer[1026];
	const unsigned char *data8 = (const unsigned char *)(data);
	if (length > 200)
		length = 200;
	for (int i = 0; i < length; i++)
		sprintf(buffer + i * 2, "%02x", data8[i]);
	if (verbose > 1)
		mqtt_verbose_log(self, "%s: = %s\n", msg, buffer);
}

int mqtt_socket_sender(mqtt_client_t *self, void *data, int length)
{
	do
	{
		int done = send(self->socket, (const char *)data, length, 0) ;
		if (done < 0)
		{
			mqtt_verbose_log(self, "Send failure!!!\n");
			return -1 ; // TODO: Handle somehow...
		}
		log_buffer(self, "socket_sender", data, done);
		length -= done ;
	} while (length > 0) ;
	return 0;
}

int mqtt_socket_avail(mqtt_client_t *self, int timeoutsec)
{
	fd_set fds;
	struct timeval timeout;

	FD_ZERO(&fds);
	timeout.tv_sec = timeoutsec;
	timeout.tv_usec = 0;

	FD_SET(self->socket, &fds); // s is a socket descriptor
	if (select(self->socket + 1, &fds, NULL, NULL, &timeout) == 1)
		return 1;
	else
		return 0;
}

int mqtt_socket_recv(mqtt_client_t *self, void *data, int length)
{
#ifdef _MSC_VER
#define MSG_DONTWAIT 0
#endif
	int result = recv(self->socket, (char *)data, length, MSG_DONTWAIT);
	if (verbose && result > 0)
		log_buffer(self, "socket_recv", data, result);
	if (result < 0) {

#ifdef _MSC_VER
		int errno;
		if ((errno = WSAGetLastError()) != WSAEWOULDBLOCK)
#else
		if (errno != EWOULDBLOCK)
#endif
			mqtt_verbose_log(self, "Recv error: %d\n", errno);
		else
			result = 0;
	}

	return result;
}

void mqtt_socket_close(mqtt_client_t *self)
{
#ifdef _MSC_VER
	closesocket(self->socket);
#else
	close(self->socket);
#endif
	self->socket = 0;
}

int mqtt_socket_client_connect(mqtt_client_t *self, const char *host, const char *port)
{
	struct addrinfo hints, *servinfo, *p;
	int rv, sockfd = -1;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0)
		return -1;

	// loop through all the results and connect to the first we can
	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
			p->ai_protocol)) == -1) {
			continue;
		}

#ifndef _MSC_VER /* Set the socket to nonblocking */
	    int flags = fcntl(sockfd, F_GETFL, 0);
	    //if (flags < 0) return false;
	    flags = flags | O_NONBLOCK;
	    if (fcntl(sockfd, F_SETFL, flags) != 0)
			mqtt_verbose_log(self, "Cannot set socket as non-blocking");
#else
		unsigned long nonblocking = 1;
		if (ioctlsocket(sockfd, FIONBIO, &nonblocking) != NO_ERROR)
			mqtt_verbose_log(self, "Cannot set socket as non-blocking");
#endif


		if (connect(sockfd, p->ai_addr, p->ai_addrlen) < 0)
#ifdef _MSC_VER
			if (WSAGetLastError() != WSAEWOULDBLOCK)
#else
			if (errno != EINPROGRESS)
#endif
			{
				mqtt_verbose_log(self, "Error in connect (%d)\n", errno) ;
#ifdef _MSC_VER
				closesocket(sockfd);
#else
				close(sockfd);
#endif
				sockfd = -1;
				continue;
			}
			else
			{
			    fd_set write_fds;
				FD_ZERO(&write_fds);            //Zero out the file descriptor set
				FD_SET(sockfd, &write_fds);     //Set the current socket file descriptor into the set

				//We are going to use select to wait for the socket to connect
				struct timeval tv;              //Time value struct declaration
				tv.tv_sec = 5;                  //The second portion of the struct
				tv.tv_usec = 0;                 //The microsecond portion of the struct

				select(sockfd + 1, NULL, &write_fds, NULL, &tv);
#ifndef _MSC_VER
                int result ;
				socklen_t result_len = sizeof(result);
				if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &result, &result_len) < 0 ||
				     result != 0) {
					close(sockfd);
					sockfd = -1;
					mqtt_verbose_log(self, "Error in waiting for connection: %d\n", result) ;
					continue ;
				}
#endif
			}

		break;
	}
	freeaddrinfo(servinfo); // all done with this structure
	if (sockfd > 0)
		self->socket = sockfd;
	return sockfd;
}



#ifdef HAVE_OPENSSL
typedef struct ssl_env_s
{
	BIO              *certbio;
	BIO              *outbio;
	const SSL_METHOD *method;
	SSL_CTX          *ctx;
} ssl_env_t;

void ssl_env_init(ssl_env_t *self)
{
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	/* ---------------------------------------------------------- *
	* Create the Input/Output BIO's.                             *
	* ---------------------------------------------------------- */
	self->certbio = BIO_new(BIO_s_file());
	self->outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	/* ---------------------------------------------------------- *
	* initialize SSL library and register algorithms             *
	* ---------------------------------------------------------- */
	if (SSL_library_init() < 0) {
		BIO_printf(self->outbio, "Could not initialize the OpenSSL library !\n");
		mqtt_verbose_log(NULL, "Could not initialize the OpenSSL library !\n");
	}

	/* ---------------------------------------------------------- *
	* Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
	* ---------------------------------------------------------- */
	self->method = SSLv23_client_method();

	/* ---------------------------------------------------------- *
	* Try to create a new SSL context                            *
	* ---------------------------------------------------------- */
	if ((self->ctx = SSL_CTX_new(self->method)) == NULL) {
		BIO_printf(self->outbio, "Unable to create a new SSL context structure.\n");
		mqtt_verbose_log(NULL, "Unable to create a new SSL context structure.\n");
    }

	/* ---------------------------------------------------------- *
	* Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
	* ---------------------------------------------------------- */
	SSL_CTX_set_options(self->ctx, SSL_OP_NO_SSLv2);
}

void ssl_env_shut(ssl_env_t *self)
{
	if (self->ctx == 0)
		return;
	SSL_CTX_free(self->ctx);
	BIO_printf(self->outbio, "Finished SSL/TLS connection with server.\n");
}

static int handle_readwrite_whishes(SSL *ssl, int sock, int err, int skip_read)
{
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sock, &fds);

	int ssl_err = SSL_get_error(ssl, err);
	switch (ssl_err)
	{
	case SSL_ERROR_WANT_READ:
		if (skip_read)
			return 0;
		else
			select(sock + 1, &fds, NULL, NULL, NULL);
		break;
	case SSL_ERROR_WANT_WRITE:
		select(sock + 1, NULL, &fds, NULL, NULL);
		break;
	default: {
    		mqtt_verbose_log(NULL, "SSL exit with error %d\n", ssl_err);
    		if (ssl_err == SSL_ERROR_SYSCALL) {
    		    mqtt_verbose_log(NULL, "Syscall: %d (%s)\n", errno, strerror(errno)) ;
    		    return -2 ;
    		}
		    usleep(500) ;
	    	return -1;
		}
	}
	return 0;
}


int mqtt_ssl_client_connect(mqtt_client_t *self, ssl_env_t *ssl_env, const char *host, const char *port)
{
	/* ---------------------------------------------------------- *
	* Create new SSL connection state object                     *
	* ---------------------------------------------------------- */
	SSL *ssl = SSL_new(ssl_env->ctx);
	/* ---------------------------------------------------------- *
	* Make the underlying TCP socket connection                  *
	* ---------------------------------------------------------- */
	//int server = create_socket(host, port, self->outbio);
	int server = mqtt_socket_client_connect(self, host, port);
	//	test_http(server);
	if (server != 0)
		mqtt_verbose_log(self, "Successfully made the TCP connection to: %s.\n", host);
	else
		return -1;

	/* ---------------------------------------------------------- *
	* Attach the SSL session to the socket descriptor            *
	* ---------------------------------------------------------- */
	SSL_set_fd(ssl, server);
	SSL_set_read_ahead(ssl, 1);
	/* ---------------------------------------------------------- *
	* Try to SSL-connect here, returns 1 for success             *
	* ---------------------------------------------------------- */
	int conn;
	mqtt_verbose_log(self, "Attempting SSL_Connect\n") ;
	while ((conn = SSL_connect(ssl)) != 1)
		for (int i = 0 ; i < 5 ; i++)
		    switch (handle_readwrite_whishes(ssl, server, conn, 0))
		    {
		    case 0:
            	mqtt_verbose_log(self, "SSL_Connect DONE!\n") ;
            	self->sock_data = ssl;
	            return 1;
	        case -2:
	            return -1 ;
		    }
    return -1 ;
}


int mqtt_ssl_sender(mqtt_client_t *self, void *data, int length)
{
	SSL *ssl = (SSL *)self->sock_data;
	do
	{
		int res = SSL_write(ssl, data, length);
		if (res > 0)
		{
			length -= res;
			log_buffer(self, "ssl_sender", data, res);
		}
		else
			if (handle_readwrite_whishes(ssl, self->socket, res, 0) < 0)
				break;
	} while (length > 0);
    if (length > 0)
        mqtt_verbose_log(self, "ssl_sender exiting with error\n");
	return length == 0;
}

int mqtt_ssl_avail(mqtt_client_t *self, int timeoutsec)
{
	SSL *ssl = (SSL *)self->sock_data;
	return SSL_pending(ssl);
}

int mqtt_ssl_recv(mqtt_client_t *self, void *data, int length)
{
	int res = 0;
	SSL *ssl = (SSL *)self->sock_data;
	do
	{
		res = SSL_read(ssl, data, length);
		if (res > 0)
			log_buffer(self, "ssl_recv", data, res);
		else
			if (handle_readwrite_whishes(ssl, self->socket, res, 1) < 0)
            {
                mqtt_verbose_log(self, "ssl_recv exiting with error\n");
				return -1;
            }
			else
				return 0;
	} while (res <= 0);
	return res;
}

void mqtt_ssl_close(mqtt_client_t *self)
{
    mqtt_verbose_log(self, "mqtt_ssl_close begin\n") ;
	SSL_free((SSL *)(self->sock_data));
    mqtt_verbose_log(self, "mqtt_ssl_close SSL close done\n") ;
	mqtt_socket_close(self);
    mqtt_verbose_log(self, "mqtt_ssl_close done\n") ;
}

#ifdef HAVE_SSL_TEST
static void mqtt_on_connect_ssl(mqtt_client_t *client)
{
	mqtt_verbose_log(client, "MQTTs connection done!\n");
}

void test_http(int server)
{
	char buffer[64];
	char test[] = "GET /index.html HTTP/1.1\nhost: 192.168.188.128\n\n";
	int result = send(server, test, strlen(test), 0);
	for (int i = 0; i < 10; i++)
	{
		usleep(1000 * 10);
		result = recv(server, buffer, sizeof(buffer), 0);
	}
}

int ssl_env_connect(ssl_env_t *self, const char *host, const char *port)
{
	int result = -1;
	mqtt_client_t client;
	/* ---------------------------------------------------------- *
	* Create new SSL connection state object                     *
	* ---------------------------------------------------------- */
	SSL *ssl = SSL_new(self->ctx);
	/* ---------------------------------------------------------- *
	* Make the underlying TCP socket connection                  *
	* ---------------------------------------------------------- */
	//int server = create_socket(host, port, self->outbio);
	int server = mqtt_socket_client_connect(&client, host, port);
		//	test_http(server);
	if (server != 0)
		BIO_printf(self->outbio, "Successfully made the TCP connection to: %s.\n", host);

	/* ---------------------------------------------------------- *
	* Attach the SSL session to the socket descriptor            *
	* ---------------------------------------------------------- */
	SSL_set_fd(ssl, server);
	SSL_set_read_ahead(ssl, 1);
	/* ---------------------------------------------------------- *
	* Try to SSL-connect here, returns 1 for success             *
	* ---------------------------------------------------------- */
	int conn;
	while ((conn = SSL_connect(ssl)) != 1)
		handle_readwrite_whishes(ssl, server, conn, 0);

	const char *pass = "DevelUsr";
	char clientid[1600];
	struct timespec ts;

 	clock_gettime(CLOCK_MONOTONIC, &ts);
	sprintf(clientid, "alight-%d", (int)(ts.tv_sec + ts.tv_nsec) % 1000000);
	mqtt_client_init(&client, clientid, 1, MQTT_TIMEOUT_SEC);
	mqtt_client_credentials(&client, "develusr", pass, strlen(pass));
	mqtt_client_callbacks(&client, &mqtt_on_connect_ssl, &browser_driver_message_handler);
	client.data = NULL;
	client.socket = server;
	client.sock_data = ssl;

	client.sender = mqtt_ssl_sender;
	client.avail = mqtt_ssl_avail;
	client.recv = mqtt_ssl_recv;
	client.shut = mqtt_ssl_close;

	mqtt_client_send(&client, &client.clientmsg);
	for (int i = 0 ; i < 100 ; i++)
		mqtt_client_loop(&client, 0);

	BIO_printf(self->outbio, "Successfully enabled SSL/TLS session to: %s.\n", host);
	mqtt_client_shutdown(&client);
	return result;
}


int test_ssl_connection(const char *host, const char *port)
{
	ssl_env_t ssl_env;
	ssl_env_init(&ssl_env);
	ssl_env_connect(&ssl_env, host, port);
	ssl_env_shut(&ssl_env);
}
ssl_env_t ssl_env = {0, 0, 0, 0};
#endif
#endif

browser_driver_t browser_driver;

int mqtt_client_transport_init(mqtt_client_t *self, const char *host, const char *port)
{
#ifdef HAVE_OPENSSL
	if (strcmp(port, "8883") == 0)
	{
		if (ssl_env.ctx == NULL)
			ssl_env_init(&ssl_env);
		if (mqtt_ssl_client_connect(self, &ssl_env, host, port) < 0)
			return -1;
		self->sender = mqtt_ssl_sender;
		self->avail  = mqtt_ssl_avail;
		self->recv   = mqtt_ssl_recv;
		self->shut   = mqtt_ssl_close;
		return 1;
	}
#endif
	if (mqtt_socket_client_connect(self, host, port) < 0)
		return -1;
	self->sender = mqtt_socket_sender;
	self->avail  = mqtt_socket_avail;
	self->recv   = mqtt_socket_recv;
	self->shut   = mqtt_socket_close;
	return 1;
}

static int token_get(FILE *fp, char *buffer, int length)
{
	int ch;
	int count = 0;

	memset(buffer, 0, length);
	while ((ch = getc(fp)) != EOF)
		switch (ch)
		{
		case ':':
			if (buffer[count] == '\0')
				buffer[count] = ch;
			else
				ungetc(ch, fp);
		case ' ':
		case '\t':
		case '\r':
		case '\n':
			return buffer[0] != '\0';
		default:
			if (count < length - 1)
				buffer[count++] = (char)ch;
			break;
		}
	return -1;
}

static int token_get_valid(FILE *fp, char *buffer, int length)
{
	do
	{
		if (token_get(fp, buffer, length) < 0)
			return 0;
	} while (buffer[0] == '\0');
	return 1;
}

static int token_expect(FILE *fp, char *buffer)
{
	char tag[MAX_NAME_LEN];

	token_get_valid(fp, tag, MAX_NAME_LEN);
	return strcmp(tag, buffer) == 0;
}

int get_hwid(const char *cpuinfo, char *hwid)
{
	char tag[MAX_NAME_LEN];
	char hwrev[MAX_NAME_LEN];

	FILE *fp = fopen(cpuinfo, "r");
	if (fp != NULL)
	{
		while (token_get_valid(fp, tag, MAX_NAME_LEN))
		{
			if (strcmp(tag, "Hardware") == 0) {
				if (token_expect(fp, ":"))
					if (!token_get_valid(fp, hwrev, MAX_NAME_LEN))
						hwrev[0] = '\0';
			}
			else if (strcmp(tag, "Serial") == 0) {
				if (token_expect(fp, ":"))
					if (token_get_valid(fp, tag, MAX_NAME_LEN)) {
						strcpy(hwid, hwrev);
						strcat(hwid, "-");
						strcat(hwid, tag);
						break;
					}
			}
		}
		fclose(fp);
		return 1;
	}
	else
		strcpy(hwid, "HWID-0001");
	return 0;
}

#ifdef HAVE_WATCHDOG
int watchdog_fd = 0 ;
#endif
void on_force_exit(int sig)
{
#ifdef HAVE_WATCHDOG
    if (watchdog_fd != 0)
        close(watchdog_fd) ;
#endif
	browser_driver_shut(&browser_driver);
#ifdef HAVE_OPENSSL
	ssl_env_shut(&ssl_env);
#endif
	exit(1) ;
}

int main(int argc, char *argv[])
{
	const char *host = "localhost";
	const char *port = "1883";
	const char *config = "dmx.cfg";
	const char *cpuinfo = "/proc/cpuinfo";
	char hw_id[MAX_NAME_LEN] = "1234";
#ifdef WIN32
	WSADATA wsaData;   // if this doesn't work

	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup failed.\n");
		exit(1);
	}
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif
    signal(SIGINT, on_force_exit) ;
	for (int i = 0; i < argc; i++)
		if (strcmp(argv[i], "--host") == 0)
			host = argv[++i];
		else if (strcmp(argv[i], "--verbose") == 0)
			verbose = 1;
		else if (strcmp(argv[i], "--vv") == 0)
			verbose = 2;
		else if (strcmp(argv[i], "--config") == 0)
			config = argv[++i];
		else if (strcmp(argv[i], "--cpuinfo") == 0)
			cpuinfo = argv[++i];
		else if (strcmp(argv[i], "--port") == 0)
			port = argv[++i];
		else if (strcmp(argv[i], "--sleep") == 0)
			sleep(atoi(argv[++i]));
		else if (strcmp(argv[i], "--log") == 0)
			log_file = argv[++i];
#ifdef HAVE_WATCHDOG
		else if (strcmp(argv[i], "--watchdog") == 0)
		{
		    watchdog_fd = open("/dev/watchdog", O_WRONLY);
		    if (watchdog_fd != 0)
		    {
	            long timeout = 30;
                ioctl(watchdog_fd, WDIOC_SETTIMEOUT, &timeout);
            }
		}
#endif
#ifdef HAVE_SSL_TEST
		else if (strcmp(argv[i], "--ssl") == 0)
			return test_ssl_connection(host, port);
#endif
	get_hwid(cpuinfo, hw_id);
	if (verbose)
		printf("HD-ID = %s\n", hw_id);
	if (browser_driver_init(&browser_driver, config, hw_id) == 0)
	{
		browser_driver_connect(&browser_driver, host, port); // failure to connect is not fatal: could be recovered later
		for (int i = 0; i < argc; i++)
			if (strcmp(argv[i], "--remote") == 0) // additional connection
				browser_driver_connect(&browser_driver, argv[++i], port);
			else if (strcmp(argv[i], "--rport") == 0)
				port = argv[++i];

		for (; ;)
		{
			browser_driver_loop(&browser_driver) ;
			if (browser_driver.stop)
				break ;
#ifdef HAVE_WATCHDOG
		    if (watchdog_fd != 0)
        		write(watchdog_fd, "\0", 1);
#endif
#ifdef _MSC_VER
			if (_kbhit())
				break;
#endif
		}
	}
	browser_driver_shut(&browser_driver);
#ifdef HAVE_OPENSSL
	ssl_env_shut(&ssl_env);
#endif
	return 0;
}
