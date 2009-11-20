CC = g++
CFLAGS = -O2 -Wall -pedantic -std=c++98
OBJDIR = ./obj
OUTDIR = ./bin

BASEOBJS = $(OBJDIR)/authority.o $(OBJDIR)/connection.o $(OBJDIR)/core.o $(OBJDIR)/hunk.o $(OBJDIR)/node.o $(OBJDIR)/non_authoritative.o $(OBJDIR)/packet.o $(OBJDIR)/peer_cache.o $(OBJDIR)/protocol.o

SIMOBJS = $(BASEOBJS) $(OBJDIR)/simulator/config.o $(OBJDIR)/simulator/simulator.o $(OBJDIR)/simulator/traffic_generator.o

all = $(OUTDIR)/simulator

$(OUTDIR)/simulator : $(SIMOBJS)
	$(CC) $(CFLAGS) $^ -lssl -lglog -lboost_system -lboost_filesystem -o $@

$(OBJDIR)/%.o : %.cpp
	$(CC) $(CFLAGS) -I. -I./simulator -c $< -o $@