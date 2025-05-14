/**
 * Remote-Port Server Application
 *
 * This server application uses libremote-port to communicate with clients.
 * Start two instances of this server to exchange information.
 * Clients can connect using netcat.
 *
 * Usage: ./rp-server <port|unix-socket-path> [--unix] [--base <addr>] [--size <size>] [--fill <min>:<max>]
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
#include <termios.h>
#include <ctype.h>
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
#define DEFAULT_BUFFER_SIZE 0x100
#define DEFAULT_BUFFER_BASE 0x3f800000

// Global variables
volatile int server_fd = -1;
struct rp_peer_state peer_state;
uint32_t next_id = 0;
pthread_mutex_t id_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t buffer_mutex = PTHREAD_MUTEX_INITIALIZER;
int using_unix_socket = 0;
char unix_socket_path[PATH_MAX] = { 0 };
volatile int keyboard_monitoring =
	1; // Flag to control keyboard monitoring thread

// Buffer-related globals
uint8_t *memory_buffer = NULL;
uint64_t buffer_base_addr = DEFAULT_BUFFER_BASE;
size_t buffer_size = DEFAULT_BUFFER_SIZE;
uint16_t fill_min = 0;
uint16_t fill_max = 0;
int custom_fill = 0;

struct client_state {
	int fd;
	int connected;
	uint32_t dev_id;
	pthread_t thread;
	struct rp_peer_state peer;
};

struct client_state clients[MAX_CLIENTS];

// Original terminal settings
struct termios orig_termios;

// Set terminal to raw mode
void set_raw_mode()
{
	struct termios raw;

	// Save original terminal settings
	tcgetattr(STDIN_FILENO, &orig_termios);

	// Set terminal to raw mode
	raw = orig_termios;
	raw.c_lflag &= ~(ECHO | ICANON);
	raw.c_cc[VMIN] = 0; // Return immediately with whatever is available
	raw.c_cc[VTIME] = 0; // No timeout

	tcsetattr(STDIN_FILENO, TCSANOW, &raw);

	// Set stdin to non-blocking
	fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);
}

// Restore original terminal settings
void restore_terminal()
{
	tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
}

// Parse a hex string to uint64_t
uint64_t parse_hex_arg(const char *str)
{
	uint64_t value;
	if (strncmp(str, "0x", 2) == 0 || strncmp(str, "0X", 2) == 0) {
		// Skip 0x prefix
		if (sscanf(str + 2, "%lx", &value) != 1) {
			fprintf(stderr, "Error parsing hex value: %s\n", str);
			return 0;
		}
	} else {
		// Try parsing as hex
		if (sscanf(str, "%lx", &value) != 1) {
			// If that fails, try parsing as decimal
			if (sscanf(str, "%lu", &value) != 1) {
				fprintf(stderr,
					"Error parsing numeric value: %s\n",
					str);
				return 0;
			}
		}
	}
	return value;
}

// Initialize memory buffer
void init_memory_buffer()
{
	// Allocate memory for the buffer
	memory_buffer = (uint8_t *)malloc(buffer_size);
	if (!memory_buffer) {
		fprintf(stderr,
			"Failed to allocate memory buffer of size 0x%zx\n",
			buffer_size);
		exit(1);
	}

	// Initialize buffer with values
	if (custom_fill) {
		srand(time(NULL));
		uint16_t range = fill_max - fill_min + 1;
		for (size_t i = 0; i < buffer_size; i++) {
			uint16_t value = fill_min + (rand() % range);
			memory_buffer[i] = value & 0xFF;
		}
		printf("Buffer initialized with values between 0x%02x and 0x%02x\n",
		       fill_min, fill_max);
	} else {
		// Fill with incrementing values from 0x00 to 0xFF and wrap around
		for (size_t i = 0; i < buffer_size; i++) {
			memory_buffer[i] = i & 0xFF;
		}
		printf("Buffer initialized with incrementing values from 0x00 to 0xFF\n");
	}

	printf("Memory buffer allocated: base=0x%lx, size=0x%zx\n",
	       buffer_base_addr, buffer_size);
}

// Clean up memory buffer
void cleanup_memory_buffer()
{
	if (memory_buffer) {
		free(memory_buffer);
		memory_buffer = NULL;
	}
}

// Signal handler for clean shutdown
void handle_signal(int sig)
{
	printf("\nReceived signal %d, shutting down...\n", sig);

	// Stop keyboard monitoring
	keyboard_monitoring = 0;

	// Restore terminal settings
	restore_terminal();

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

	// Clean up memory buffer
	cleanup_memory_buffer();

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

	printf("\nReceived valid HELLO packet (version %d.%d)\n",
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

	printf("\nReceived interrupt: line=%u, val=%u\n", pkt->interrupt.line,
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

// Send an interrupt to all connected clients
void send_interrupt_to_clients(uint32_t line, uint64_t vector, uint8_t val)
{
	struct rp_pkt_interrupt pkt;
	size_t len;
	struct timespec ts;
	int64_t timestamp;
	int clients_sent = 0;

	// Get current timestamp
	clock_gettime(CLOCK_MONOTONIC, &ts);
	timestamp = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;

	// Send interrupt to all connected clients
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].connected) {
			len = rp_encode_interrupt(get_next_id(),
						  clients[i].dev_id, &pkt,
						  timestamp, line, vector, val);

			rp_safe_write(clients[i].fd, &pkt, len);
			clients_sent++;
		}
	}

	if (clients_sent > 0) {
		printf("Sent manual interrupt to %d clients (line=%u, val=%u)\n",
		       clients_sent, line, val);
	} else {
		printf("No clients connected to receive interrupt\n");
	}
}

// Handle Read command - modified to use memory buffer
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

	printf("\nReceived read: addr=0x%lx, len=%u\n", pkt->busaccess.addr,
	       pkt->busaccess.len);

	// Initialize response parameters
	rp_encode_busaccess_in_rsp_init(&in, pkt);
	in.clk = timestamp;

	// Check if address is in our buffer range
	uint64_t read_addr = pkt->busaccess.addr;
	uint32_t read_len = pkt->busaccess.len;
	uint32_t data_size = read_len;

	// Lock buffer mutex for thread safety
	pthread_mutex_lock(&buffer_mutex);

	if (read_addr >= buffer_base_addr &&
	    read_addr < buffer_base_addr + buffer_size) {
		// Calculate offset into our buffer
		uint64_t offset = read_addr - buffer_base_addr;

		// Check if requested length would go beyond buffer end
		if (offset + read_len > buffer_size) {
			printf("Warning: Read extends beyond buffer end. Truncating.\n");
			data_size = buffer_size - offset;
		}

		// Set response status to OK
		in.attr |= RP_RESP_OK << RP_BUS_RESP_SHIFT;
	} else {
		// Address out of range
		printf("Warning: Read address 0x%lx is outside buffer range (0x%lx-0x%lx)\n",
		       read_addr, buffer_base_addr,
		       buffer_base_addr + buffer_size - 1);
		in.attr |= RP_RESP_ADDR_ERROR << RP_BUS_RESP_SHIFT;
		data_size = 0;
	}

	// Ensure we're not allocating more space than we can handle
	if (data_size >
	    BUFFER_SIZE - sizeof(struct rp_pkt_busaccess_ext_base)) {
		fprintf(stderr,
			"Warning: Requested read size too large, truncating\n");
		data_size =
			BUFFER_SIZE - sizeof(struct rp_pkt_busaccess_ext_base);
	}

	in.size = data_size; // Update size in response

	// Allocate space for the response
	rp_dpkt_alloc(&dpkt,
		      sizeof(struct rp_pkt_busaccess_ext_base) + data_size);

	// Encode the response
	plen = rp_encode_busaccess(&peer_state, &dpkt.pkt->busaccess_ext_base,
				   &in);

	// Set up data pointer
	data = rp_busaccess_tx_dataptr(&peer_state,
				       &dpkt.pkt->busaccess_ext_base);

	// Copy data from our buffer if the address was valid
	if (data && data_size > 0 && read_addr >= buffer_base_addr &&
	    read_addr < buffer_base_addr + buffer_size) {
		uint64_t offset = read_addr - buffer_base_addr;
		memcpy(data, memory_buffer + offset, data_size);

		// Print first few bytes for debugging
		printf("Data: ");
		for (unsigned int i = 0; i < data_size && i <= 1024; i++) {
			printf("%02x ", data[i]);
		}
		if (data_size > 1024)
			printf("...");
		printf("\n");
	}

	// Unlock buffer mutex
	pthread_mutex_unlock(&buffer_mutex);

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

// Handle Write command - modified to update memory buffer
void handle_write(int client_fd, struct rp_pkt *pkt, uint8_t *data, size_t len)
{
	struct rp_pkt_busaccess resp = { 0 };
	int64_t timestamp;
	struct timespec ts;
	struct rp_encode_busaccess_in in = { 0 };
	int write_result = RP_RESP_OK;

	// Get current timestamp
	clock_gettime(CLOCK_MONOTONIC, &ts);
	timestamp = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;

	printf("\nReceived write: addr=0x%lx, len=%u\n", pkt->busaccess.addr,
	       pkt->busaccess.len);

	// Print the data (for demo purposes)
	printf("Data: ");
	for (size_t i = 0; i < len && i <= 1024; i++) {
		printf("%02x ", data[i]);
	}
	if (len > 1024) {
		printf("... (%u bytes total)\n", len);
	}
	printf("\n");

	// Check if address is in our buffer range and update buffer
	uint64_t write_addr = pkt->busaccess.addr;

	// Lock buffer mutex for thread safety
	pthread_mutex_lock(&buffer_mutex);

	if (write_addr >= buffer_base_addr &&
	    write_addr < buffer_base_addr + buffer_size) {
		// Calculate offset into our buffer
		uint64_t offset = write_addr - buffer_base_addr;

		// Check if requested length would go beyond buffer end
		if (offset + len > buffer_size) {
			printf("Warning: Write extends beyond buffer end. Truncating.\n");
			len = buffer_size - offset;
		}

		// Update our buffer
		memcpy(memory_buffer + offset, data, len);
		printf("Buffer updated at offset 0x%lx, length %zu\n", offset,
		       len);

	} else {
		// Address out of range
		printf("Warning: Write address 0x%lx is outside buffer range (0x%lx-0x%lx)\n",
		       write_addr, buffer_base_addr,
		       buffer_base_addr + buffer_size - 1);
		write_result = RP_RESP_ADDR_ERROR;
	}

	// Unlock buffer mutex
	pthread_mutex_unlock(&buffer_mutex);

	// If not posted, send a response
	if (!(pkt->hdr.flags & RP_PKT_FLAGS_posted)) {
		RemotePortDynPkt dpkt = { 0 };
		size_t plen;

		rp_encode_busaccess_in_rsp_init(&in, pkt);
		in.clk = timestamp;
		in.attr |= write_result << RP_BUS_RESP_SHIFT;

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

// Send a write to all connected clients
void send_write_to_clients(uint64_t addr, uint8_t *data, size_t len)
{
	int clients_sent = 0;
	struct timespec ts;
	int64_t timestamp;

	// Get current timestamp
	clock_gettime(CLOCK_MONOTONIC, &ts);
	timestamp = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;

	// Update our internal buffer first if address is in range
	pthread_mutex_lock(&buffer_mutex);
	if (addr >= buffer_base_addr && addr < buffer_base_addr + buffer_size) {
		uint64_t offset = addr - buffer_base_addr;
		if (offset + len <= buffer_size) {
			memcpy(memory_buffer + offset, data, len);
			printf("Local buffer updated at offset 0x%lx\n",
			       offset);
		} else {
			printf("Warning: Write extends beyond buffer end, truncating\n");
			memcpy(memory_buffer + offset, data,
			       buffer_size - offset);
		}
	} else {
		printf("Warning: Write address 0x%lx outside buffer range\n",
		       addr);
	}
	pthread_mutex_unlock(&buffer_mutex);

	// Send to all connected clients
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].connected) {
			RemotePortDynPkt dpkt = { 0 };
			size_t plen;
			struct rp_encode_busaccess_in in = { 0 };

			in.cmd = RP_CMD_write;
			in.id = get_next_id();
			in.dev = clients[i].dev_id;
			in.clk = timestamp;
			in.master_id =
				1; // Using 1 as a default master ID for manual writes
			in.addr = addr;
			in.attr = 0; // No special attributes
			in.size = len;
			in.width = len; // Using size as width for simplicity
			in.stream_width = len;

			rp_dpkt_alloc(&dpkt,
				      sizeof(struct rp_pkt_busaccess_ext_base));
			plen = rp_encode_busaccess(
				&clients[i].peer, &dpkt.pkt->busaccess_ext_base,
				&in);

			// Send the packet header
			if (rp_safe_write(clients[i].fd, dpkt.pkt, plen) !=
			    plen) {
				perror("Failed to write packet header to client");
				rp_dpkt_free(&dpkt);
				continue;
			}

			// Send the data
			if (rp_safe_write(clients[i].fd, data, len) !=
			    (ssize_t)len) {
				perror("Failed to write data to client");
			} else {
				clients_sent++;
			}

			rp_dpkt_free(&dpkt);
		}
	}

	if (clients_sent > 0) {
		printf("Sent write to %d clients (addr=0x%lx, len=%zu)\n",
		       clients_sent, addr, len);
	} else {
		printf("No clients connected to receive write\n");
	}
}

// Function to collect input for a manual write
void handle_manual_write()
{
	char input_buffer[1024] = { 0 };
	uint8_t data_buffer[BUFFER_SIZE] = { 0 };
	size_t data_len = 0;
	uint64_t addr = buffer_base_addr; // Default to buffer base address

	// Switch back to canonical mode for input
	struct termios old_term = orig_termios;
	struct termios new_term = orig_termios;
	new_term.c_lflag |= ICANON | ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

	// Clear any pending input
	int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK);

	// Prompt for address
	printf("\nEnter write address (hex, default=0x%lx): 0x",
	       buffer_base_addr);
	fflush(stdout);

	if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
		// Remove newline
		size_t len = strlen(input_buffer);
		if (len > 0 && input_buffer[len - 1] == '\n') {
			input_buffer[len - 1] = '\0';
		}

		// Parse address if provided
		if (strlen(input_buffer) > 0) {
			addr = parse_hex_arg(input_buffer);
		}
	}

	// Prompt for data
	printf("Enter data to write (ASCII text, press Enter to send): ");
	fflush(stdout);

	if (fgets(input_buffer, sizeof(input_buffer), stdin) != NULL) {
		// Remove newline
		size_t len = strlen(input_buffer);
		if (len > 0 && input_buffer[len - 1] == '\n') {
			input_buffer[len - 1] = '\0';
			len--;
		}

		// Copy input as ASCII data
		data_len = (len > BUFFER_SIZE) ? BUFFER_SIZE : len;
		memcpy(data_buffer, input_buffer, data_len);

		// Display what we're sending
		printf("Writing %zu bytes to address 0x%lx:\n", data_len, addr);
		printf("ASCII: %s\n", input_buffer);
		printf("HEX:   ");
		for (size_t i = 0; i < data_len; i++) {
			printf("%02x ", data_buffer[i]);
		}
		printf("\n");

		// Send the write
		send_write_to_clients(addr, data_buffer, data_len);
	}

	// Restore terminal settings
	tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
	fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

	printf("Write operation completed.\n");
}

// Keyboard monitoring thread function
void *keyboard_monitor_thread(void *arg)
{
	char c;

	printf("Keyboard monitor started. Commands:\n");
	printf("  'i' - Send an interrupt to all clients\n");
	printf("  'w' - Send a write to all clients\n");
	printf("  'q' - Quit\n");

	while (keyboard_monitoring) {
		// Check for key press
		if (read(STDIN_FILENO, &c, 1) > 0) {
			switch (c) {
			case 'i':
			case 'I':
				// Send interrupt with line 1, vector 0, value 1
				send_interrupt_to_clients(1, 0, 1);
				break;

			case 'w':
			case 'W':
				// Handle manual write
				handle_manual_write();
				break;

			case 'q':
			case 'Q':
				// Trigger graceful shutdown
				printf("Quit requested via keyboard\n");
				keyboard_monitoring = 0;
				kill(getpid(), SIGINT);
				return NULL;

			default:
				// Ignore other keys
				break;
			}
		}

		// Sleep a bit to avoid consuming too much CPU
		usleep(50000); // 50ms
	}

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

// Parse the fill range argument (min:max)
void parse_fill_range(const char *arg)
{
	const char *colon_pos = strchr(arg, ':');
	if (!colon_pos) {
		fprintf(stderr,
			"Invalid fill range format. Use min:max (e.g., 0x00:0xFF)\n");
		exit(1);
	}

	// Split the string at the colon
	char min_str[32] = { 0 };
	char max_str[32] = { 0 };

	strncpy(min_str, arg, colon_pos - arg);
	strncpy(max_str, colon_pos + 1, sizeof(max_str) - 1);

	// Parse the min and max values
	fill_min = parse_hex_arg(min_str);
	fill_max = parse_hex_arg(max_str);

	if (fill_min > fill_max) {
		fprintf(stderr,
			"Fill min (0x%04x) must be less than or equal to max (0x%04x)\n",
			fill_min, fill_max);
		exit(1);
	}

	custom_fill = 1;
}

// Display usage information
void print_usage(const char *program)
{
	fprintf(stderr, "Usage: %s <port|unix-socket-path> [options]\n",
		program);
	fprintf(stderr, "Options:\n");
	fprintf(stderr,
		"  --unix               Use Unix domain socket instead of TCP\n");
	fprintf(stderr,
		"  --base <addr>        Set buffer base address (hex, default: 0x%x)\n",
		DEFAULT_BUFFER_BASE);
	fprintf(stderr,
		"  --size <size>        Set buffer size (hex/dec, default: 0x%x)\n",
		DEFAULT_BUFFER_SIZE);
	fprintf(stderr,
		"  --fill <min>:<max>   Set buffer fill range (hex, default: incrementing 0x00-0xFF)\n");
	fprintf(stderr, "\nCommands during execution:\n");
	fprintf(stderr,
		"  i                    Send interrupt to all clients\n");
	fprintf(stderr,
		"  w                    Write data to the buffer and broadcast to clients\n");
	fprintf(stderr, "  q                    Quit the application\n");
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
	pthread_t keyboard_thread;

	// Initialize client array
	for (int i = 0; i < MAX_CLIENTS; i++) {
		clients[i].connected = 0;
	}

	// Parse command line arguments
	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	// First argument is port or socket path
	port = atoi(argv[1]);
	if (port <= 0) {
		// Not a valid port, assume it's a socket path for later
		socket_path = argv[1];
	}

	// Process other optional arguments
	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--unix") == 0) {
			using_unix_socket = 1;
			strncpy(unix_socket_path, socket_path,
				sizeof(unix_socket_path) - 1);
		} else if (strcmp(argv[i], "--base") == 0 && i + 1 < argc) {
			buffer_base_addr = parse_hex_arg(argv[++i]);
		} else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
			buffer_size = parse_hex_arg(argv[++i]);
			if (buffer_size == 0) {
				buffer_size = DEFAULT_BUFFER_SIZE;
				fprintf(stderr,
					"Invalid buffer size, using default: 0x%zx\n",
					buffer_size);
			}
		} else if (strcmp(argv[i], "--fill") == 0 && i + 1 < argc) {
			parse_fill_range(argv[++i]);
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			print_usage(argv[0]);
			return 1;
		}
	}

	// Initialize the memory buffer
	init_memory_buffer();

	// Set terminal to raw mode for keyboard input
	set_raw_mode();

	// Set up signal handlers
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	// Initialize peer state
	memset(&peer_state, 0, sizeof(peer_state));

	// Start keyboard monitoring thread
	if (pthread_create(&keyboard_thread, NULL, keyboard_monitor_thread,
			   NULL) != 0) {
		perror("Failed to create keyboard monitoring thread");
		restore_terminal();
		cleanup_memory_buffer();
		return 1;
	}

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
		cleanup_memory_buffer();
		return 1;
	}

	printf("Remote-Port server listening...\n");
	printf("Memory buffer: base=0x%lx, size=0x%zx\n", buffer_base_addr,
	       buffer_size);
	printf("Commands: 'i'=send interrupt, 'w'=write data, 'q'=quit\n");

	// Main server loop
	while (keyboard_monitoring) {
		// Set up the file descriptors for select
		fd_set readfds;
		struct timeval tv;

		FD_ZERO(&readfds);
		FD_SET(server_fd, &readfds);

		// Use a short timeout to allow for checking keyboard_monitoring flag
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		int select_result =
			select(server_fd + 1, &readfds, NULL, NULL, &tv);

		if (select_result < 0) {
			if (errno == EINTR) {
				continue; // Interrupted by signal, just continue
			}
			perror("select");
			break;
		}

		if (select_result == 0) {
			// Timeout - just continue to check the keyboard_monitoring flag
			continue;
		}

		if (!FD_ISSET(server_fd, &readfds)) {
			continue;
		}

		// Accept a new client connection
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

	// Wait for keyboard monitoring thread to finish
	keyboard_monitoring = 0;
	pthread_join(keyboard_thread, NULL);

	// Restore terminal settings
	restore_terminal();

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

	// Clean up memory buffer
	cleanup_memory_buffer();

	// Remove unix socket file if we were using one
	if (using_unix_socket && unix_socket_path[0] != '\0') {
		unlink(unix_socket_path);
		printf("Removed Unix socket: %s\n", unix_socket_path);
	}

	return 0;
}
