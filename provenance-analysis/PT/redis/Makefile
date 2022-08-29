# Path
REDIS_DIR = $(shell pwd)
HIREDIS_DIR = $(shell pwd)/hiredis

# Dynamic Lib
HIREDIS_SO = $(HIREDIS_DIR)/libhiredis.so

# Scr
REDIS_SCR = $(wildcard $(REDIS_DIR)/*.cpp)

# Object
REDIS_OBJ = $(patsubst %.cpp, %.o, $(REDIS_SCR))
DRIVER_OBJ = $(REDIS_DIR)/driver.o

# Option
VER = normal
ifeq ($(VER), debug)
	OPT += -O0 -g -DDEBUG
else
	OPT += -O3 -ggdb
endif

# Compile
CPP = g++
WARNINGS = -Wall -Wextra
CXXFLAGS  = $(WARNINGS) $(OPT) -std=c++17 

TARGET = driver

all: $(REDIS_OBJ) $(TARGET)

$(TARGET): $(REDIS_OBJ) $(HIREDIS_SO) $(DRIVER_OBJ)
	$(CPP) $(CXXFLAGS) $^ -o $@

$(REDIS_OBJ):%.o : %.cpp
	$(CPP) $(CXXFLAGS) -c $<

$(HIREDIS_SO): 
	(cd $(HIREDIS_DIR) && $(MAKE) all)

.PHONY: clean

clean:
	rm -f *.o *.a $(TARGET)
