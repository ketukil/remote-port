/**
 * Remote-Port Client Utility
 *
 * This utility allows sending Remote-Port protocol messages
 * through a TCP or Unix domain socket connection, making it easier to test the rp-server.
 *
 * Usage: ./rp-client <host> <port> <command> [options]
 *    or: ./rp-client --unix <socket-path> <command> [options]
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
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

extern "C" {
#include "remote-port-proto.h"
#include "safeio.h"
}
#define BUFFER_SIZE 4096
#define DEFAULT_UNIX_SOCKET "/tmp/rp-server.sock"

// Global variables
struct rp_peer_state peer_state;
int socket_fd = -1;
pthread_t receive_thread;
volatile int running = 1;

// Get current timestamp in nanoseconds
int64_t get_timestamp()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

// Connect to server using TCP
int connect_tcp_server(const char *host, int port)
{
	struct sockaddr_in server_addr;
	struct hostent *server;
	int fd;

	// Create socket
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("Error creating socket");
		return -1;
	}

	// Get server info
	server = gethostbyname(host);
	if (server == NULL) {
		fprintf(stderr, "Error: no such host\n");
		close(fd);
		return -1;
	}

	// Set up server address
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
	server_addr.sin_port = htons(port);

	// Connect to server
	if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
	    0) {
		perror("Error connecting to server");
		close(fd);
		return -1;
	}

	return fd;
}

// Connect to server using Unix domain socket
int connect_unix_server(const char *socket_path)
{
	struct sockaddr_un server_addr;
	int fd;

	// Create socket
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("Error creating Unix socket");
		return -1;
	}

	// Set up server address
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strncpy(server_addr.sun_path, socket_path,
		sizeof(server_addr.sun_path) - 1);

	// Connect to server
	if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
	    0) {
		perror("Error connecting to Unix socket");
		close(fd);
		return -1;
	}

	return fd;
}

// Send HELLO message
void send_hello()
{
	uint32_t caps[] = { CAP_BUSACCESS_EXT_BASE, CAP_WIRE_POSTED_UPDATES,
			    CAP_ATS };
	struct rp_pkt_hello pkt = { 0 };
	size_t len;

	printf("[client] Sending HELLO packet\n");

	len = rp_encode_hello_caps(1, 0, &pkt, RP_VERSION_MAJOR,
				   RP_VERSION_MINOR, caps, caps,
				   sizeof(caps) / sizeof(caps[0]));

	rp_safe_write(socket_fd, &pkt, len);
	rp_safe_write(socket_fd, caps, sizeof(caps));
}

// Send INTERRUPT message
void send_interrupt(uint32_t line, uint8_t val)
{
	struct rp_pkt_interrupt pkt = { 0 };
	size_t len;
	int64_t timestamp = get_timestamp();

	printf("[client] Sending INTERRUPT: line=%u, val=%u\n", line, val);

	len = rp_encode_interrupt(2, 0, &pkt, timestamp, line, 0, val);
	rp_safe_write(socket_fd, &pkt, len);
}

// Send READ message
void send_read(uint64_t addr, uint32_t size)
{
	struct rp_pkt_busaccess pkt = { 0 };
	size_t len;
	int64_t timestamp = get_timestamp();

	printf("[client] Sending READ: addr=0x%lx, size=%u\n", addr, size);

	len = rp_encode_read(RP_CMD_read, 0, &pkt, timestamp, 0, addr, 0, size, 0, size);
	rp_safe_write(socket_fd, &pkt, len);
}

// Send WRITE message
void send_write(uint64_t addr, const char *data_hex)
{
	struct rp_pkt_busaccess pkt = { 0 };
	size_t len, data_len;
	int64_t timestamp = get_timestamp();
	uint8_t *data;

	// Convert hex string to binary
	data_len = strlen(data_hex) / 2;
	data = (uint8_t *)malloc(data_len);
	if (!data) {
		perror("Failed to allocate memory for data");
		return;
	}

	for (size_t i = 0; i < data_len; i++) {
		sscanf(data_hex + i * 2, "%2hhx", &data[i]);
	}

	printf("[client] Sending WRITE: addr=0x%lx, size=%zu\n", addr, data_len);

	len = rp_encode_write(RP_CMD_write, 0, &pkt, timestamp, 0, addr, 0, data_len, 0,
			      data_len);
	rp_safe_write(socket_fd, &pkt, len);
	rp_safe_write(socket_fd, data, data_len);

	free(data);
}

// Send SYNC message
void send_sync()
{
	struct rp_pkt_sync pkt = { 0 };
	size_t len;
	int64_t timestamp = get_timestamp();

	printf("[client] Sending SYNC\n");

	len = rp_encode_sync(RP_CMD_sync, 0, &pkt, timestamp);
	rp_safe_write(socket_fd, &pkt, len);
}

// Receive and process messages from server
void *receive_thread_func(void *arg)
{
	uint8_t buffer[BUFFER_SIZE];
	struct rp_pkt *pkt = (struct rp_pkt *)buffer;
	ssize_t r;

	while (running) {
		// Read packet header
		r = read(socket_fd, &pkt->hdr, sizeof(pkt->hdr));
		if (r <= 0) {
			if (r < 0)
				perror("read");
			printf("[client] Server disconnected\n");
			running = 0;
			break;
		}

		// Decode header
		rp_decode_hdr(pkt);

		// Read rest of packet
		if (pkt->hdr.len > 0) {
			r = read(socket_fd, buffer + sizeof(pkt->hdr),
				 pkt->hdr.len);
			if (r <= 0) {
				if (r < 0)
					perror("read");
				printf("[client] Server disconnected\n");
				running = 0;
				break;
			}
		}

		// Decode payload
		rp_decode_payload(pkt);

		// Process packet based on command
		switch (pkt->hdr.cmd) {
		case RP_CMD_hello:
			printf("[client] Received HELLO: version=%d.%d, caps_len=%d\n",
			       pkt->hello.version.major,
			       pkt->hello.version.minor, pkt->hello.caps.len);

			if (pkt->hello.caps.len) {
				void *caps =
					(char *)pkt + pkt->hello.caps.offset;
				rp_process_caps(&peer_state, caps,
						pkt->hello.caps.len);
			}
			break;

		case RP_CMD_sync:
			printf("[client] Received SYNC: timestamp=%ld\n",
			       pkt->sync.timestamp);
			break;

		case RP_CMD_interrupt:
			printf("[client] Received INTERRUPT: line=%u, val=%u\n",
			       pkt->interrupt.line, pkt->interrupt.val);
			break;

		case RP_CMD_read:
			printf("[client] Received READ: addr=0x%lx, len=%u\n",
			       pkt->busaccess.addr, pkt->busaccess.len);
			break;

		case RP_CMD_write:
			printf("[client] Received WRITE: addr=0x%lx, len=%u\n",
			       pkt->busaccess.addr, pkt->busaccess.len);
			break;

		default:
			printf("[client] Received unknown command: %d\n", pkt->hdr.cmd);
			break;
		}
	}

	return NULL;
}

// Interactive mode
void interactive_mode()
{
	char cmd[256];
	char *token;

	printf("[client] Interactive mode. Type 'help' for commands, 'quit' to exit.\n");

	while (running) {
		printf("[client] > ");
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			break;
		}

		// Remove newline
		cmd[strcspn(cmd, "\n")] = 0;

		// Skip empty lines
		if (strlen(cmd) == 0) {
			continue;
		}

		// Parse command
		token = strtok(cmd, " ");
		if (!token)
			continue;

		if (strcmp(token, "quit") == 0 || strcmp(token, "exit") == 0) {
			break;
		} else if (strcmp(token, "help") == 0) {
			printf("Commands:\n");
			printf("  hello                   - Send HELLO packet\n");
			printf("  interrupt <line> <val>  - Send INTERRUPT\n");
			printf("  read <addr> <size>      - Send READ request\n");
			printf("  write <addr> <data_hex> - Send WRITE request\n");
			printf("  sync                    - Send SYNC request\n");
			printf("  quit/exit               - Exit program\n");
		} else if (strcmp(token, "hello") == 0) {
			send_hello();
		} else if (strcmp(token, "interrupt") == 0) {
			token = strtok(NULL, " ");
			uint32_t line = token ? atoi(token) : 0;
			token = strtok(NULL, " ");
			uint8_t val = token ? atoi(token) : 1;
			send_interrupt(line, val);
		} else if (strcmp(token, "read") == 0) {
			token = strtok(NULL, " ");
			uint64_t addr = token ? strtoull(token, NULL, 0) : 0;
			token = strtok(NULL, " ");
			uint32_t size = token ? atoi(token) : 4;
			send_read(addr, size);
		} else if (strcmp(token, "write") == 0) {
			token = strtok(NULL, " ");
			uint64_t addr = token ? strtoull(token, NULL, 0) : 0;
			token = strtok(NULL, " ");
			if (token) {
				send_write(addr, token);
			} else {
				printf("[client] Error: Missing data for write command\n");
			}
		} else if (strcmp(token, "sync") == 0) {
			send_sync();
		} else {
			printf("[client] Unknown command: %s\n", token);
		}
	}
}

// Print usage
void print_usage(const char *program)
{
	fprintf(stderr, "Usage: %s <host> <port> <command> [options]\n",
		program);
	fprintf(stderr, "   or: %s --unix <socket-path> <command> [options]\n",
		program);
	fprintf(stderr, "Commands:\n");
	fprintf(stderr, "  hello                   - Send HELLO packet\n");
	fprintf(stderr, "  interrupt <line> <val>  - Send INTERRUPT\n");
	fprintf(stderr, "  read <addr> <size>      - Send READ request\n");
	fprintf(stderr, "  write <addr> <data_hex> - Send WRITE request\n");
	fprintf(stderr, "  sync                    - Send SYNC request\n");
	fprintf(stderr,
		"  listen                  - Just listen for messages\n");
	fprintf(stderr, "  interactive             - Interactive mode\n");
}

int main(int argc, char *argv[])
{
	const char *host;
	int port;
	const char *command;
	const char *unix_socket_path = DEFAULT_UNIX_SOCKET;
	int using_unix_socket = 0;
	int arg_offset = 0;

	// Check arguments
	if (argc < 3) {
		print_usage(argv[0]);
		return 1;
	}

	// Check if using Unix socket
	if (strcmp(argv[1], "--unix") == 0) {
		using_unix_socket = 1;
		if (argc < 4) {
			print_usage(argv[0]);
			return 1;
		}
		unix_socket_path = argv[2];
		command = argv[3];
		arg_offset = 4;
	} else {
		if (argc < 4) {
			print_usage(argv[0]);
			return 1;
		}
		host = argv[1];
		port = atoi(argv[2]);
		command = argv[3];
		arg_offset = 4;

		if (port <= 0) {
			fprintf(stderr, "Invalid port: %s\n", argv[2]);
			return 1;
		}
	}

	// Initialize peer state
	memset(&peer_state, 0, sizeof(peer_state));

	// Connect to server
	if (using_unix_socket) {
		printf("[client] Connecting to Unix socket: %s\n", unix_socket_path);
		socket_fd = connect_unix_server(unix_socket_path);
	} else {
		printf("[client] Connecting to %s:%d\n", host, port);
		socket_fd = connect_tcp_server(host, port);
	}

	if (socket_fd < 0) {
		return 1;
	}

	// Start receive thread
	if (pthread_create(&receive_thread, NULL, receive_thread_func, NULL) !=
	    0) {
		perror("Failed to create receive thread");
		close(socket_fd);
		return 1;
	}

	// Process command
	if (strcmp(command, "hello") == 0) {
		send_hello();
	} else if (strcmp(command, "interrupt") == 0) {
		if (argc < arg_offset + 2) {
			fprintf(stderr,
				"Missing arguments for interrupt command\n");
			return 1;
		}
		uint32_t line = atoi(argv[arg_offset]);
		uint8_t val = atoi(argv[arg_offset + 1]);
		send_interrupt(line, val);
	} else if (strcmp(command, "read") == 0) {
		if (argc < arg_offset + 2) {
			fprintf(stderr, "Missing arguments for read command\n");
			return 1;
		}
		uint64_t addr = strtoull(argv[arg_offset], NULL, 0);
		uint32_t size = atoi(argv[arg_offset + 1]);
		send_read(addr, size);
	} else if (strcmp(command, "write") == 0) {
		if (argc < arg_offset + 2) {
			fprintf(stderr,
				"Missing arguments for write command\n");
			return 1;
		}
		uint64_t addr = strtoull(argv[arg_offset], NULL, 0);
		send_write(addr, argv[arg_offset + 1]);
	} else if (strcmp(command, "sync") == 0) {
		send_sync();
	} else if (strcmp(command, "listen") == 0) {
		printf("[client] Listening for messages. Press Ctrl+C to exit.\n");
		// Just wait for messages
		while (running) {
			sleep(1);
		}
	} else if (strcmp(command, "interactive") == 0) {
		interactive_mode();
	} else {
		fprintf(stderr, "Unknown command: %s\n", command);
		print_usage(argv[0]);
		running = 0;
	}

	// Wait a moment to let responses arrive
	sleep(1);

	// Clean up
	running = 0;
	pthread_join(receive_thread, NULL);
	close(socket_fd);

	return 0;
}
