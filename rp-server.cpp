/**
 * Remote-Port Server Application
 *
 * This server application uses libremote-port to communicate with clients.
 * Start two instances of this server to exchange information.
 * Clients can connect using netcat.
 *
 * Usage: ./rp-server <port|unix-socket-path> [--unix]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
extern "C" {
#include "remote-port-proto.h"
#include "remote-port-sk.h"
#include "safeio.h"
}

#define DEFAULT_PORT 5555
#define DEFAULT_UNIX_SOCKET "/tmp/rp-server.sock"
#define BUFFER_SIZE 64 * 1024
#define MAX_CLIENTS 10
#define PATH_MAX 1024

// Global variables
volatile int server_fd = -1;
struct rp_peer_state peer_state;
uint32_t next_id = 0;
pthread_mutex_t id_mutex = PTHREAD_MUTEX_INITIALIZER;
int using_unix_socket = 0;
char unix_socket_path[PATH_MAX] = { 0 };

struct client_state {
	int fd;
	int connected;
	uint32_t dev_id;
	pthread_t thread;
	struct rp_peer_state peer;
};

struct client_state clients[MAX_CLIENTS];

// Signal handler for clean shutdown
void handle_signal(int sig)
{
	printf("\nReceived signal %d, shutting down...\n", sig);

	// Close server socket
	if (server_fd >= 0) {
		close(server_fd);
	}

	// Clean up client connections
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].connected) {
			close(clients[i].fd);
			clients[i].connected = 0;
		}
	}

	// Remove unix socket file if we were using one
	if (using_unix_socket && unix_socket_path[0] != '\0') {
		unlink(unix_socket_path);
		printf("Removed Unix socket: %s\n", unix_socket_path);
	}

	exit(0);
}

// Get next available packet ID
uint32_t get_next_id()
{
	uint32_t id;
	pthread_mutex_lock(&id_mutex);
	id = next_id++;
	pthread_mutex_unlock(&id_mutex);
	return id;
}

// Initialize client slot
void init_client(int index, int client_fd)
{
	clients[index].fd = client_fd;
	clients[index].connected = 1;
	clients[index].dev_id = index;
	memset(&clients[index].peer, 0, sizeof(struct rp_peer_state));
}

bool is_packed_valid(struct rp_pkt *pkt)
{
	if (pkt->hdr.cmd > RP_CMD_max) {
		fprintf(stderr, "Invalid command: %d > %d\n", pkt->hdr.cmd,
			RP_CMD_max);
		return false;
	}

	if (pkt->hdr.len > BUFFER_SIZE) {
		fprintf(stderr, "Packet too large: %u > %u\n", pkt->hdr.len,
			BUFFER_SIZE);
		return false;
	}

	return true;
}
// Send HELLO message to client
void send_hello(int client_fd)
{
	uint32_t caps[] = { CAP_BUSACCESS_EXT_BASE, CAP_WIRE_POSTED_UPDATES,
			    CAP_ATS };
	struct rp_pkt_hello pkt = { 0 };
	size_t len;
	uint32_t id = get_next_id();

	printf("Sending HELLO packet (id=%u)\n", id);

	len = rp_encode_hello_caps(id, 0, &pkt, RP_VERSION_MAJOR,
				   RP_VERSION_MINOR, caps, caps,
				   sizeof(caps) / sizeof(caps[0]));

	// Send the header and capabilities
	rp_safe_write(client_fd, &pkt, len);
	rp_safe_write(client_fd, caps, sizeof(caps));
}

// Process HELLO message from client
void process_hello(int client_fd, struct rp_pkt *pkt)
{
	if (pkt->hello.version.major != RP_VERSION_MAJOR) {
		fprintf(stderr,
			"RP Version mismatch: remote=%d.%d local=%d.%d\n",
			pkt->hello.version.major, pkt->hello.version.minor,
			RP_VERSION_MAJOR, RP_VERSION_MINOR);
		close(client_fd);
		return;
	}

	printf("Received valid HELLO packet (version %d.%d)\n",
	       pkt->hello.version.major, pkt->hello.version.minor);

	if (pkt->hello.caps.len) {
		void *caps = (char *)pkt + pkt->hello.caps.offset;
		rp_process_caps(&peer_state, caps, pkt->hello.caps.len);
		printf("Processed %d capability entries\n",
		       pkt->hello.caps.len);
	}
}

// Handle SYNC command
void handle_sync(int client_fd, struct rp_pkt *pkt)
{
	struct rp_pkt_sync resp = { 0 };
	size_t len;
	int64_t timestamp;

	// Current timestamp in ns
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	timestamp = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;

	// Encode sync response
	len = rp_encode_sync_resp(pkt->hdr.id, pkt->hdr.dev, &resp, timestamp);
	rp_safe_write(client_fd, &resp, len);
}

// Handle INTERRUPT command
void handle_interrupt(int client_fd, struct rp_pkt *pkt)
{
	struct rp_pkt_interrupt resp = { 0 };
	size_t len;
	int64_t timestamp;
	uint32_t flags = pkt->hdr.flags;

	// Get current timestamp
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	timestamp = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;

	printf("Received interrupt: line=%u, val=%u\n", pkt->interrupt.line,
	       pkt->interrupt.val);

	// Only send response if not posted
	if (!(peer_state.caps.wire_posted_updates &&
	      (flags & RP_PKT_FLAGS_posted))) {
		len = rp_encode_interrupt_f(pkt->hdr.id, pkt->hdr.dev, &resp,
					    timestamp, pkt->interrupt.line,
					    pkt->interrupt.vector,
					    pkt->interrupt.val,
					    RP_PKT_FLAGS_response);
		rp_safe_write(client_fd, &resp, len);
	}

	// Forward to other clients (simplified for demo)
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].connected && clients[i].fd != client_fd) {
			len = rp_encode_interrupt_f(
				get_next_id(), clients[i].dev_id, &resp,
				timestamp, pkt->interrupt.line,
				pkt->interrupt.vector, pkt->interrupt.val, 0);
			rp_safe_write(clients[i].fd, &resp, len);
		}
	}
}

// Handle Read command
void handle_read(int client_fd, struct rp_pkt *pkt)
{
	size_t plen;
	uint8_t *data;
	int64_t timestamp;
	struct timespec ts;
	struct rp_encode_busaccess_in in = { 0 };
	RemotePortDynPkt dpkt = { 0 };

	// Get current timestamp
	clock_gettime(CLOCK_MONOTONIC, &ts);
	timestamp = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;

	printf("Received read: addr=0x%lx, len=%u\n", pkt->busaccess.addr,
	       pkt->busaccess.len);

	// Initialize response parameters
	rp_encode_busaccess_in_rsp_init(&in, pkt);
	in.clk = timestamp;
	in.attr |= RP_RESP_OK << RP_BUS_RESP_SHIFT;

	// Ensure we're not allocating more space than we can handle
	uint32_t data_size = pkt->busaccess.len;
	if (data_size >
	    BUFFER_SIZE - sizeof(struct rp_pkt_busaccess_ext_base)) {
		fprintf(stderr,
			"Warning: Requested read size too large, truncating\n");
		data_size =
			BUFFER_SIZE - sizeof(struct rp_pkt_busaccess_ext_base);
		in.size = data_size; // Update size in response
	}

	// Allocate space for the response
	rp_dpkt_alloc(&dpkt,
		      sizeof(struct rp_pkt_busaccess_ext_base) + data_size);

	// Encode the response
	plen = rp_encode_busaccess(&peer_state, &dpkt.pkt->busaccess_ext_base,
				   &in);

	// Generate some demo data (incrementing values)
	data = rp_busaccess_tx_dataptr(&peer_state,
				       &dpkt.pkt->busaccess_ext_base);
	if (data) {
		for (unsigned int i = 0; i < data_size; i++) {
			data[i] = i & 0xFF;
		}
	}

	// Send the response header
	if (rp_safe_write(client_fd, dpkt.pkt, plen) != plen) {
		perror("Failed to write read response header");
		rp_dpkt_free(&dpkt);
		return;
	}

	// Send the data
	if (data_size > 0 && data) {
		if (rp_safe_write(client_fd, data, data_size) != data_size) {
			perror("Failed to write read response data");
		}
	}

	// Free allocated memory
	rp_dpkt_free(&dpkt);
}
// Handle Write command
void handle_write(int client_fd, struct rp_pkt *pkt, uint8_t *data, size_t len)
{
	struct rp_pkt_busaccess resp = { 0 };
	int64_t timestamp;
	struct timespec ts;
	struct rp_encode_busaccess_in in = { 0 };

	// Get current timestamp
	clock_gettime(CLOCK_MONOTONIC, &ts);
	timestamp = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;

	printf("Received write: addr=0x%lx, len=%u\n", pkt->busaccess.addr,
	       pkt->busaccess.len);

	// Print the data (for demo purposes)
	printf("Data: ");
	for (size_t i = 0; i < len && i < 16; i++) {
		printf("%02x ", data[i]);
	}
	if (len > 16)
		printf("...");
	printf("\n");

	// If not posted, send a response
	if (!(pkt->hdr.flags & RP_PKT_FLAGS_posted)) {
		RemotePortDynPkt dpkt = { 0 };
		size_t plen;

		rp_encode_busaccess_in_rsp_init(&in, pkt);
		in.clk = timestamp;
		in.attr |= RP_RESP_OK << RP_BUS_RESP_SHIFT;

		rp_dpkt_alloc(&dpkt, sizeof(struct rp_pkt_busaccess_ext_base));
		plen = rp_encode_busaccess(&peer_state,
					   &dpkt.pkt->busaccess_ext_base, &in);

		rp_safe_write(client_fd, dpkt.pkt, plen);
		rp_dpkt_free(&dpkt);
	}

	// Forward to other clients (simplified for demo)
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].connected && clients[i].fd != client_fd) {
			RemotePortDynPkt dpkt = { 0 };
			size_t plen;

			in.cmd = RP_CMD_write;
			in.id = get_next_id();
			in.dev = clients[i].dev_id;
			in.clk = timestamp;
			in.master_id = pkt->busaccess.master_id;
			in.addr = pkt->busaccess.addr;
			in.attr = pkt->busaccess.attributes;
			in.size = pkt->busaccess.len;
			in.width = pkt->busaccess.width;
			in.stream_width = pkt->busaccess.stream_width;

			rp_dpkt_alloc(&dpkt,
				      sizeof(struct rp_pkt_busaccess_ext_base));
			plen = rp_encode_busaccess(
				&clients[i].peer, &dpkt.pkt->busaccess_ext_base,
				&in);

			rp_safe_write(clients[i].fd, dpkt.pkt, plen);
			rp_safe_write(clients[i].fd, data, len);

			rp_dpkt_free(&dpkt);
		}
	}
}

// Client handler thread
void *client_handler(void *arg)
{
	int client_idx = *((int *)arg);
	int client_fd = clients[client_idx].fd;
	uint8_t buffer[BUFFER_SIZE];
	struct rp_pkt *pkt = (struct rp_pkt *)buffer;
	ssize_t r;
	int hello_received = 0;
	time_t last_ping_time = 0;

	free(arg); // Free the memory allocated for the argument

	// Send HELLO packet to initialize connection
	send_hello(client_fd);

	// For netcat clients that don't know how to respond with HELLO,
	// we'll treat them as connected after a timeout
	time_t connect_time = time(NULL);

	// Main client processing loop
	while (1) {
		fd_set readfds;
		struct timeval tv;
		int ready;

		// Set up select timeout - 5 seconds
		FD_ZERO(&readfds);
		FD_SET(client_fd, &readfds);
		tv.tv_sec = 5;
		tv.tv_usec = 0;

		ready = select(client_fd + 1, &readfds, NULL, NULL, &tv);

		// If no data after 5 seconds and we have another client, send some demo data
		time_t current_time = time(NULL);
		if (ready == 0 || !FD_ISSET(client_fd, &readfds)) {
			// If we haven't received a HELLO in 10 seconds, assume it's just netcat
			if (!hello_received &&
			    (current_time - connect_time > 10)) {
				printf("Client %d: No HELLO received, assuming simple client\n",
				       client_idx);
				hello_received =
					1; // Mark as "initialized" anyway
			}

			// Send periodic updates to other clients if we're "initialized"
			if (hello_received &&
			    (current_time - last_ping_time > 5)) {
				last_ping_time = current_time;

				// Send a demo interrupt to all other clients
				for (int i = 0; i < MAX_CLIENTS; i++) {
					if (clients[i].connected &&
					    clients[i].fd != client_fd) {
						struct rp_pkt_interrupt demo_pkt;
						size_t len;
						struct timespec ts;
						clock_gettime(CLOCK_MONOTONIC,
							      &ts);
						int64_t timestamp =
							(int64_t)ts.tv_sec *
								1000000000LL +
							ts.tv_nsec;

						len = rp_encode_interrupt(
							get_next_id(),
							clients[i].dev_id,
							&demo_pkt, timestamp, 0,
							0, 1);

						printf("Sending demo interrupt to client %d\n",
						       i);
						rp_safe_write(clients[i].fd,
							      &demo_pkt, len);
					}
				}
			}

			continue;
		}

		// Read packet header
		r = rp_safe_read(client_fd, &pkt->hdr, sizeof(pkt->hdr));
		if (r <= 0) {
			break; // Client disconnected
		}

		// Decode header
		rp_decode_hdr(pkt);

		if (is_packed_valid(pkt) == false) {
			fprintf(stderr, "should be skipped\n");
			//continue; // Skip processing this packet
		}

		// Read rest of packet
		if (pkt->hdr.len > 0) {
			r = rp_safe_read(client_fd, buffer + sizeof(pkt->hdr),
					 pkt->hdr.len);
			if (r <= 0) {
				break; // Client disconnected
			}
		}

		// Decode payload
		rp_decode_payload(pkt);

		// Process packet based on command
		switch (pkt->hdr.cmd) {
		case RP_CMD_hello:
			process_hello(client_fd, pkt);
			hello_received = 1;
			break;

		case RP_CMD_sync:
			handle_sync(client_fd, pkt);
			break;

		case RP_CMD_interrupt:
			handle_interrupt(client_fd, pkt);
			break;

		case RP_CMD_read:
			handle_read(client_fd, pkt);
			break;

		case RP_CMD_write: {
			// For write commands, we need to read the data
			uint8_t *data =
				buffer + sizeof(pkt->hdr) +
				(pkt->busaccess.attributes &
						 RP_BUS_ATTR_EXT_BASE ?
					 sizeof(pkt->busaccess_ext_base) -
						 sizeof(pkt->hdr) :
					 sizeof(pkt->busaccess) -
						 sizeof(pkt->hdr));

			handle_write(client_fd, pkt, data, pkt->busaccess.len);
			break;
		}

		default:
			printf("Unsupported command: %d\n", pkt->hdr.cmd);
			break;
		}
	}

	printf("Client %d disconnected\n", client_idx);
	close(client_fd);
	clients[client_idx].connected = 0;

	return NULL;
}

// Set up TCP socket server
int setup_tcp_server(int port)
{
	struct sockaddr_in server_addr;
	int fd;
	int yes = 1;

	// Create socket
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	// Set socket options
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("setsockopt");
		close(fd);
		return -1;
	}

	// Set up server address
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port);

	// Bind socket
	if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
	    0) {
		perror("bind");
		close(fd);
		return -1;
	}

	// Listen for connections
	if (listen(fd, MAX_CLIENTS) < 0) {
		perror("listen");
		close(fd);
		return -1;
	}

	return fd;
}

// Set up Unix domain socket server
int setup_unix_server(const char *socket_path)
{
	struct sockaddr_un server_addr;
	int fd;

	// Create socket
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	// Remove any existing socket file
	unlink(socket_path);

	// Set up server address
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strncpy(server_addr.sun_path, socket_path,
		sizeof(server_addr.sun_path) - 1);

	// Bind socket
	if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
	    0) {
		perror("bind");
		close(fd);
		return -1;
	}

	// Listen for connections
	if (listen(fd, MAX_CLIENTS) < 0) {
		perror("listen");
		close(fd);
		return -1;
	}

	return fd;
}

// Display usage information
void print_usage(const char *program)
{
	fprintf(stderr, "Usage: %s <port|unix-socket-path> [--unix]\n",
		program);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  --unix    Use Unix domain socket instead of TCP\n");
}

int main(int argc, char *argv[])
{
	int port = DEFAULT_PORT;
	const char *socket_path = DEFAULT_UNIX_SOCKET;
	struct sockaddr_in client_addr_in;
	struct sockaddr_un client_addr_un;
	struct sockaddr *client_addr;
	socklen_t client_len;
	int client_fd;

	// Initialize client array
	for (int i = 0; i < MAX_CLIENTS; i++) {
		clients[i].connected = 0;
	}

	// Parse command line arguments
	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	// Check if using unix socket
	if (argc > 2 && strcmp(argv[2], "--unix") == 0) {
		using_unix_socket = 1;
		socket_path = argv[1];
		strncpy(unix_socket_path, socket_path,
			sizeof(unix_socket_path) - 1);
	} else {
		port = atoi(argv[1]);
		if (port <= 0) {
			fprintf(stderr, "Invalid port: %s\n", argv[1]);
			return 1;
		}
	}

	// Set up signal handlers
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	// Initialize peer state
	memset(&peer_state, 0, sizeof(peer_state));

	// Set up server socket
	if (using_unix_socket) {
		printf("Setting up Unix domain socket server on %s\n",
		       socket_path);
		server_fd = setup_unix_server(socket_path);
		client_addr = (struct sockaddr *)&client_addr_un;
		client_len = sizeof(client_addr_un);
	} else {
		printf("Setting up TCP server on port %d\n", port);
		server_fd = setup_tcp_server(port);
		client_addr = (struct sockaddr *)&client_addr_in;
		client_len = sizeof(client_addr_in);
	}

	if (server_fd < 0) {
		fprintf(stderr, "Failed to set up server\n");
		return 1;
	}

	printf("Remote-Port server listening...\n");

	// Main server loop
	while (1) {
		client_fd = accept(server_fd, client_addr, &client_len);
		if (client_fd < 0) {
			perror("accept");
			continue;
		}

		if (using_unix_socket) {
			printf("New client connected on Unix socket\n");
		} else {
			printf("New client connected from %s:%d\n",
			       inet_ntoa(client_addr_in.sin_addr),
			       ntohs(client_addr_in.sin_port));
		}

		// Find an available client slot
		int i;
		for (i = 0; i < MAX_CLIENTS; i++) {
			if (!clients[i].connected) {
				break;
			}
		}

		if (i == MAX_CLIENTS) {
			printf("Too many clients, connection rejected\n");
			close(client_fd);
		} else {
			init_client(i, client_fd);

			// Create thread to handle client
			int *idx = (int *)malloc(sizeof(int));
			*idx = i;
			if (pthread_create(&clients[i].thread, NULL,
					   client_handler, idx) != 0) {
				perror("pthread_create");
				close(client_fd);
				clients[i].connected = 0;
				free(idx);
			} else {
				pthread_detach(clients[i].thread);
			}
		}
	}

	return 0;
}