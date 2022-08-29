# Path
PT_DIR = $(shell pwd)
DISTORM_DIR = $(PT_DIR)/distorm

# Include
DISTORM_INC = -I$(DISTORM_DIR)/include

# Scr
PT_SCR = $(wildcard $(PT_DIR)/*.c)

# Object
DRIVER_OBJ = driver.o
DRIVER_CSV_OBJ = driver-csv.o
DISTORM_OBJ = $(DISTORM_DIR)/distorm3.a
PT_OBJ = $(patsubst %.c, %.o, $(PT_SCR))

# Option (debug/progress)
VER = normal
ifeq ($(VER), debug)
	OPT += -O0 -g -DDEBUG
else
	OPT += -O3
endif

# Compile
CC = gcc
CPP = g++
WARNINGS = -Wall -Wextra
CFLAGS  = $(WARNINGS) $(OPT)
CXXFLAGS  = $(WARNINGS) $(OPT) -std=c++17

# Target
TARGET = driver 

all: $(TARGET) $(TARGET_CSV) $(PT_OBJ) $(DISTORM_OBJ)

$(TARGET): $(PT_OBJ) $(DRIVER_OBJ) $(DISTORM_OBJ) 
	$(CPP) $(CXXFLAGS) $^ -o $@

$(TARGET_CSV): $(PT_OBJ) $(DRIVER_CSV_OBJ) $(DISTORM_OBJ)
	$(CPP) $(CXXFLAGS) $^ -o $@

$(DRIVER_OBJ): driver.cpp
	$(CPP) $(CXXFLAGS) $(DISTORM_INC) -c $<

$(PT_OBJ): %.o:%.c
	$(CC) $(CFLAGS) $(DISTORM_INC) -c $<

$(DISTORM_OBJ):
	make -C $(DISTORM_DIR)/make/linux

.PHONY: clean

clean:
	rm -f *.o *.a $(TARGET)
	rm -f *.o *.a $(TARGET_CSV)
