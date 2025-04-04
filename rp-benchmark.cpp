/**
 * Remote-Port Benchmark Utility
 *
 * This tool measures the data transfer rates achievable with the Remote-Port
 * protocol by performing a series of READ and WRITE operations of various sizes.
 *
 * Usage: ./rp-benchmark <host> <port> [options]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>

extern "C"
{
#include "remote-port-proto.h"
#include "safeio.h"
}

#define BUFFER_SIZE (16 * 1024 * 1024) // 16MB buffer for large transfers
#define MAX_PACKET_SIZE (1024 * 1024)  // 1MB max packet size

// Benchmark configuration
struct benchmark_config
{
    const char *host;   // Server hostname
    int port;           // Server port
    int num_iterations; // Number of iterations for each test
    int min_size;       // Minimum transfer size
    int max_size;       // Maximum transfer size
    int step_factor;    // Multiply size by this factor each step
    int verbose;        // Enable verbose output
};

// Global variables
struct rp_peer_state peer_state;
int socket_fd = -1;
pthread_t receive_thread;
volatile int running = 1;
struct benchmark_config config;
uint8_t *send_buffer;    // Buffer for sending data
uint8_t *receive_buffer; // Buffer for receiving data

// Timing functions
struct timespec timer_start()
{
    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    return start_time;
}

// Return elapsed time in seconds
double timer_elapsed(struct timespec start_time)
{
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    return (end_time.tv_sec - start_time.tv_sec) +
           (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;
}

// Get current timestamp in nanoseconds
int64_t get_timestamp()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

// Connect to server
int connect_to_server(const char *host, int port)
{
    struct sockaddr_in server_addr;
    struct hostent *server;
    int fd;

    // Create socket
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror("Error creating socket");
        return -1;
    }

    // Get server info
    server = gethostbyname(host);
    if (server == NULL)
    {
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
    if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Error connecting to server");
        close(fd);
        return -1;
    }

    return fd;
}

// Send HELLO message
void send_hello()
{
    uint32_t caps[] = {
        CAP_BUSACCESS_EXT_BASE,
        CAP_WIRE_POSTED_UPDATES,
        CAP_ATS};
    struct rp_pkt_hello pkt = {0};
    size_t len;

    if (config.verbose)
    {
        printf("Sending HELLO packet\n");
    }

    len = rp_encode_hello_caps(1, 0, &pkt, RP_VERSION_MAJOR, RP_VERSION_MINOR,
                               caps, caps, sizeof(caps) / sizeof(caps[0]));

    rp_safe_write(socket_fd, &pkt, len);
    rp_safe_write(socket_fd, caps, sizeof(caps));
}

// Send WRITE message for benchmarking
void send_write_benchmark(uint64_t addr, uint32_t size, uint32_t id)
{
    struct rp_pkt_busaccess pkt = {0};
    size_t len;
    int64_t timestamp = get_timestamp();

    // Prepare benchmark data (simple pattern)
    for (uint32_t i = 0; i < size; i++)
    {
        send_buffer[i] = (uint8_t)(i & 0xFF);
    }

    if (config.verbose)
    {
        printf("Sending WRITE: addr=0x%lx, size=%u, id=%u\n", addr, size, id);
    }

    // Use posted writes for higher throughput
    len = rp_encode_write(id, 0, &pkt, timestamp, 0, addr, RP_PKT_FLAGS_posted,
                          size, 0, size);

    rp_safe_write(socket_fd, &pkt, len);
    rp_safe_write(socket_fd, send_buffer, size);
}

// Send READ message for benchmarking
void send_read_benchmark(uint64_t addr, uint32_t size, uint32_t id)
{
    struct rp_pkt_busaccess pkt = {0};
    size_t len;
    int64_t timestamp = get_timestamp();

    if (config.verbose)
    {
        printf("Sending READ: addr=0x%lx, size=%u, id=%u\n", addr, size, id);
    }

    len = rp_encode_read(id, 0, &pkt, timestamp, 0, addr, 0, size, 0, size);
    rp_safe_write(socket_fd, &pkt, len);
}

// Wait for a specific READ response
int wait_for_read_response(uint32_t id, uint32_t expected_size, uint8_t *data, double timeout_seconds)
{
    time_t start_time = time(NULL);
    uint8_t header_buffer[sizeof(struct rp_pkt_busaccess)];
    struct rp_pkt *pkt = (struct rp_pkt *)header_buffer;
    ssize_t r;

    // Keep reading until we get the response we want or timeout
    while (difftime(time(NULL), start_time) < timeout_seconds)
    {
        // Set up select to wait for data with timeout
        fd_set readfds;
        struct timeval tv;

        FD_ZERO(&readfds);
        FD_SET(socket_fd, &readfds);
        tv.tv_sec = 1; // 1 second timeout
        tv.tv_usec = 0;

        int select_result = select(socket_fd + 1, &readfds, NULL, NULL, &tv);
        if (select_result <= 0)
        {
            continue; // Timeout or error, try again
        }

        // Read packet header
        r = rp_safe_read(socket_fd, header_buffer, sizeof(pkt->hdr));
        if (r <= 0)
        {
            if (r < 0)
                perror("read");
            return -1; // Error or disconnect
        }

        // Decode header
        rp_decode_hdr(pkt);

        // Read rest of header (not including data payload)
        if (pkt->hdr.len > 0)
        {
            size_t header_payload_size = pkt->hdr.len;
            if (pkt->hdr.cmd == RP_CMD_read && (pkt->hdr.flags & RP_PKT_FLAGS_response))
            {
                // For read responses, the payload includes the data, which we'll read separately
                header_payload_size = sizeof(pkt->busaccess) - sizeof(pkt->hdr);
            }

            r = rp_safe_read(socket_fd, header_buffer + sizeof(pkt->hdr), header_payload_size);
            if (r <= 0)
            {
                if (r < 0)
                    perror("read");
                return -1;
            }
        }

        // If this is a read response for our ID
        if (pkt->hdr.cmd == RP_CMD_read &&
            (pkt->hdr.flags & RP_PKT_FLAGS_response) &&
            pkt->hdr.id == id)
        {

            // Decode payload
            rp_decode_payload(pkt);

            // Read the actual data
            if (pkt->busaccess.len > 0)
            {
                r = rp_safe_read(socket_fd, data, pkt->busaccess.len);
                if (r <= 0)
                {
                    if (r < 0)
                        perror("read");
                    return -1;
                }

                if (config.verbose)
                {
                    printf("Received READ response: id=%u, size=%u\n", id, pkt->busaccess.len);
                }

                return (int)pkt->busaccess.len;
            }
        }
        else
        {
            // Handle other packets if needed
            if (config.verbose)
            {
                printf("Received other packet: cmd=%u, id=%u\n", pkt->hdr.cmd, pkt->hdr.id);
            }

            // Skip any data payload for other packets
            if (pkt->hdr.cmd == RP_CMD_write ||
                (pkt->hdr.cmd == RP_CMD_read && !(pkt->hdr.flags & RP_PKT_FLAGS_response)))
            {
                // Decode payload to get length
                rp_decode_payload(pkt);
                if (pkt->busaccess.len > 0)
                {
                    // Discard the data by reading into our buffer
                    r = rp_safe_read(socket_fd, receive_buffer, pkt->busaccess.len);
                    if (r <= 0)
                    {
                        if (r < 0)
                            perror("read");
                        return -1;
                    }
                }
            }
        }
    }

    // Timeout
    fprintf(stderr, "Timeout waiting for read response (id=%u)\n", id);
    return -1;
}

// Benchmark write performance
void benchmark_write(int size)
{
    struct timespec start_time;
    double elapsed_time;
    double bandwidth_mbps;
    uint64_t total_bytes = 0;
    uint32_t id = 100; // Start ID for benchmark packets

    printf("Benchmarking WRITE operations with size %d bytes...\n", size);

    start_time = timer_start();

    for (int i = 0; i < config.num_iterations; i++)
    {
        send_write_benchmark(0x1000 + i * size, size, id++);
        total_bytes += size;
    }

    elapsed_time = timer_elapsed(start_time);
    bandwidth_mbps = (total_bytes * 8) / (elapsed_time * 1000000);

    printf("WRITE %d bytes x %d iterations: %.2f seconds, %.2f Mbps\n",
           size, config.num_iterations, elapsed_time, bandwidth_mbps);
}

// Benchmark read performance
void benchmark_read(int size)
{
    struct timespec start_time;
    double elapsed_time;
    double bandwidth_mbps;
    uint64_t total_bytes = 0;
    uint32_t id = 500; // Start ID for benchmark packets
    int bytes_received;

    printf("Benchmarking READ operations with size %d bytes...\n", size);

    start_time = timer_start();

    for (int i = 0; i < config.num_iterations; i++)
    {
        send_read_benchmark(0x1000 + i * size, size, id);

        bytes_received = wait_for_read_response(id, size, receive_buffer, 60.0);
        id++;

        if (bytes_received < 0)
        {
            fprintf(stderr, "Error receiving read response\n");
            continue;
        }

        total_bytes += bytes_received;
    }

    elapsed_time = timer_elapsed(start_time);
    bandwidth_mbps = (total_bytes * 8) / (elapsed_time * 1000000);

    printf("READ %d bytes x %d iterations: %.2f seconds, %.2f Mbps\n",
           size, config.num_iterations, elapsed_time, bandwidth_mbps);
}

// Print usage
void print_usage(const char *program)
{
    fprintf(stderr, "Usage: %s <host> <port> [options]\n", program);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i <iterations> : Number of iterations for each test (default: 100)\n");
    fprintf(stderr, "  -m <min_size>   : Minimum transfer size in bytes (default: 16)\n");
    fprintf(stderr, "  -M <max_size>   : Maximum transfer size in bytes (default: 65536)\n");
    fprintf(stderr, "  -f <factor>     : Size step factor (default: 4)\n");
    fprintf(stderr, "  -v              : Verbose output\n");
    fprintf(stderr, "  -h              : Show this help message\n");
}

// Parse command line arguments
int parse_args(int argc, char *argv[])
{
    int opt;

    // Set default values
    config.num_iterations = 100;
    config.min_size = 16;
    config.max_size = 65536;
    config.step_factor = 4;
    config.verbose = 0;

    if (argc < 3)
    {
        print_usage(argv[0]);
        return -1;
    }

    config.host = argv[1];
    config.port = atoi(argv[2]);

    if (config.port <= 0)
    {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return -1;
    }

    while ((opt = getopt(argc - 2, argv + 2, "i:m:M:f:vh")) != -1)
    {
        switch (opt)
        {
        case 'i':
            config.num_iterations = atoi(optarg);
            if (config.num_iterations <= 0)
            {
                fprintf(stderr, "Invalid number of iterations: %s\n", optarg);
                return -1;
            }
            break;
        case 'm':
            config.min_size = atoi(optarg);
            if (config.min_size <= 0)
            {
                fprintf(stderr, "Invalid minimum size: %s\n", optarg);
                return -1;
            }
            break;
        case 'M':
            config.max_size = atoi(optarg);
            if (config.max_size <= 0)
            {
                fprintf(stderr, "Invalid maximum size: %s\n", optarg);
                return -1;
            }
            break;
        case 'f':
            config.step_factor = atoi(optarg);
            if (config.step_factor <= 1)
            {
                fprintf(stderr, "Invalid step factor: %s\n", optarg);
                return -1;
            }
            break;
        case 'v':
            config.verbose = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return -1;
        default:
            fprintf(stderr, "Unknown option: %c\n", opt);
            print_usage(argv[0]);
            return -1;
        }
    }

    // Validate combinations
    if (config.min_size > config.max_size)
    {
        fprintf(stderr, "Minimum size cannot be greater than maximum size\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    // Parse command line arguments
    if (parse_args(argc, argv) != 0)
    {
        return 1;
    }

    printf("Remote-Port Benchmark Tool\n");
    printf("Host: %s, Port: %d\n", config.host, config.port);
    printf("Iterations: %d, Min size: %d, Max size: %d, Step factor: %d\n",
           config.num_iterations, config.min_size, config.max_size, config.step_factor);

    // Allocate buffers
    send_buffer = (uint8_t*)malloc(BUFFER_SIZE);
    receive_buffer = (uint8_t*)malloc(BUFFER_SIZE);
    if (!send_buffer || !receive_buffer)
    {
        fprintf(stderr, "Failed to allocate memory for buffers\n");
        return 1;
    }

    // Initialize peer state
    memset(&peer_state, 0, sizeof(peer_state));

    // Connect to server
    socket_fd = connect_to_server(config.host, config.port);
    if (socket_fd < 0)
    {
        free(send_buffer);
        free(receive_buffer);
        return 1;
    }

    // Send HELLO packet to initialize communication
    send_hello();

    // Wait a moment for server to process HELLO
    sleep(1);

    printf("\n=== Starting Benchmark ===\n\n");

    // Benchmark WRITE operations with increasing sizes
    for (int size = config.min_size;
         size <= config.max_size && size <= MAX_PACKET_SIZE;
         size *= config.step_factor)
    {
        benchmark_write(size);
    }

    printf("\n");

    // Benchmark READ operations with increasing sizes
    for (int size = config.min_size;
         size <= config.max_size && size <= MAX_PACKET_SIZE;
         size *= config.step_factor)
    {
        benchmark_read(size);
    }

    printf("\n=== Benchmark Complete ===\n");

    // Clean up
    close(socket_fd);
    free(send_buffer);
    free(receive_buffer);

    return 0;
}