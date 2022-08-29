# Path
TAINT_DIR = $(shell pwd)
REDIS_DIR = $(shell dirname $(TAINT_DIR))/redis
HIREDIS_DIR = $(REDIS_DIR)/hiredis

# Scr
TAINT_SCR = $(filter-out $(TAINT_DIR)/driver.cpp, $(wildcard $(TAINT_DIR)/*.cpp))
REDIS_SCR = $(filter-out $(REDIS_DIR)/driver.cpp, $(wildcard $(REDIS_DIR)/*.cpp))

# Dynamic Lib
HIREDIS_SO = $(HIREDIS_DIR)/libhiredis.so

# Object
TAINT_OBJ = $(patsubst %.cpp, %.o, $(TAINT_SCR))
REDIS_OBJ = $(patsubst %.cpp, %.o, $(REDIS_SCR))
DRIVER_OBJ = $(TAINT_DIR)/driver.o
OBJ = $(DRIVER_OBJ) $(TAINT_OBJ) $(REDIS_OBJ) $(HIREDIS_SO)

# Option
export VER = normal
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

all: $(TAINT_OBJ) $(TARGET)

$(TARGET): $(OBJ)
	$(CPP) $(CXXFLAGS) $^ -o $@

$(TAINT_OBJ):%.o : %.cpp
	$(CPP) $(CXXFLAGS) -c $<

$(REDIS_OBJ): %.o:%.cpp
	(cd $(REDIS_DIR) && $(MAKE) $(REDIS_OBJ))

.PHONY: clean

clean:
	rm -f *.o *.a $(TARGET)
	(cd $(REDIS_DIR) && $(MAKE) clean)
