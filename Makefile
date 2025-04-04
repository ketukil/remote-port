# Combined Makefile for Remote-Port server/client and SystemC applications

# C compiler for Remote-Port server/client
CC = gcc
# C++ compiler for SystemC applications
CXX = g++
# Make
MAKE = make


# Determine SystemC libraries - using SystemC 3.0.0 which is in /usr/local/lib
SYSTEMC_LIBDIR = /usr/local/lib
SYSTEMC_LIBRARY = -lsystemc-3.0.0
SYSTEMC_INCLUDE = -I/usr/local/include

# Basic compilation flags
CFLAGS = -Wall -g -Og
CXXFLAGS = -Wall -g -Og
LDFLAGS = -pthread

# Path to the libremote-port
RP_INCLUDE = -Ilibrp/
RP_STATIC_LIB = librp/libremote-port.a
RP_SHARED_LIB = librp/libremote-port.so
RP_LIBDIR = -Llibrp/
RP_LIB = -lremote-port

# Define Remote-Port server/client targets
RP_SERVER = rp-server
RP_CLIENT = rp-client
RP_BENCHMARK = rp-benchmark
RP_BENCHMARK_SHARED = rp-benchmark-shared

# Default target builds everything
all: libremote-port tools benchmark
tools: $(RP_SERVER) $(RP_CLIENT)
benchmark: $(RP_BENCHMARK)
benchmark-shared: $(RP_BENCHMARK_SHARED) 

# Remote-Port server and client
# $(RP_SERVER): rp-server.cpp $(RP_STATIC_LIB) sc_main_stub.o
# 	$(CXX) $(CXXFLAGS) $(RP_INCLUDE) $(SYSTEMC_INCLUDE) -o $@ $< sc_main_stub.o $(RP_STATIC_LIB) -L$(SYSTEMC_LIBDIR) $(SYSTEMC_LIBRARY) $(LDFLAGS)

# $(RP_CLIENT): rp-client.cpp $(RP_STATIC_LIB) sc_main_stub.o
# 	$(CXX) $(CXXFLAGS) $(RP_INCLUDE) $(SYSTEMC_INCLUDE) -o $@ $< sc_main_stub.o $(RP_STATIC_LIB) -L$(SYSTEMC_LIBDIR) $(SYSTEMC_LIBRARY) $(LDFLAGS)

# $(RP_BENCHMARK): rp-benchmark.cpp $(RP_STATIC_LIB) sc_main_stub.o
# 	$(CXX) $(CXXFLAGS) $(RP_INCLUDE) $(SYSTEMC_INCLUDE) -o $@ $< sc_main_stub.o $(RP_STATIC_LIB) -L$(SYSTEMC_LIBDIR) $(SYSTEMC_LIBRARY) $(LDFLAGS)

# $(RP_BENCHMARK_SHARED): rp-benchmark.cpp $(RP_SHARED_LIB) sc_main_stub.o
# 	$(CXX) $(CXXFLAGS) $(RP_INCLUDE) $(SYSTEMC_INCLUDE) -o $@ $< sc_main_stub.o $(RP_LIBDIR) $(RP_LIB) -L$(SYSTEMC_LIBDIR) $(SYSTEMC_LIBRARY) $(LDFLAGS) -Wl,-rpath=libremote-port/ -Wl,-rpath=$(SYSTEMC_LIBDIR)

# Remote-Port server and client
$(RP_SERVER): rp-server.cpp $(RP_STATIC_LIB) 
	$(CXX) $(CXXFLAGS) $(RP_INCLUDE) -o $@ $< $(RP_STATIC_LIB) $(LDFLAGS)

$(RP_CLIENT): rp-client.cpp $(RP_STATIC_LIB) 
	$(CXX) $(CXXFLAGS) $(RP_INCLUDE) -o $@ $< $(RP_STATIC_LIB)  $(LDFLAGS)

$(RP_BENCHMARK): rp-benchmark.cpp $(RP_STATIC_LIB)
	$(CXX) $(CXXFLAGS) $(RP_INCLUDE) -o $@ $< $(RP_STATIC_LIB) $(LDFLAGS)

$(RP_BENCHMARK_SHARED): rp-benchmark.cpp $(RP_SHARED_LIB)
	$(CXX) $(CXXFLAGS) $(RP_INCLUDE) -o $@ $< $(RP_LIBDIR) $(RP_LIB) $(LDFLAGS) -Wl,-rpath=librp/ 

libremote-port:
	$(MAKE) -C librp
	$(MAKE) -C librp copy

# Additional source file to define sc_main if needed
sc_main_stub.o: sc_main_stub.cpp
	$(CXX) $(CXXFLAGS) $(SYSTEMC_INCLUDE) -c $< -o $@

# Create the sc_main stub file if it doesn't exist
sc_main_stub.cpp:
	@echo "#include <systemc>" > $@
	@echo "int sc_main(int argc, char* argv[]) { return 0; }" >> $@

# Clean build artifacts
clean:
	rm -f *.o *.so *.a $(RP_SERVER) $(RP_CLIENT) $(RP_BENCHMARK) $(RP_BENCHMARK_SHARED) 
	make -C librp clean


.PHONY: all tools benchmark librp