# Path
CURR_DIR = $(shell pwd)
PT_DIR = $(CURR_DIR)/pt
DISTORM_DIR = $(PT_DIR)/distorm
AUDIT_DIR = $(CURR_DIR)/audit
TAINT_DIR = $(CURR_DIR)/taint
REDIS_DIR = $(CURR_DIR)/redis
HIREDIS_DIR = $(REDIS_DIR)/hiredis

# Include
export DISTORM_INC = -I$(DISTORM_DIR)/include

# Dynamic Lib
export HIREDIS_SO = $(HIREDIS_DIR)/libhiredis.so
export JSON_LIB = -ljsoncpp
LIBS = $(strip $(JSON_LIB))

# Scr
PT_SCR = $(wildcard $(PT_DIR)/*.c)
TAINT_SCR = $(filter-out $(TAINT_DIR)/driver.cpp, $(wildcard $(TAINT_DIR)/*.cpp))
REDIS_SCR = $(filter-out $(REDIS_DIR)/driver.cpp, $(wildcard $(REDIS_DIR)/*.cpp))
AUDIT_SCR = $(filter-out $(AUDIT_DIR)/driver.cpp, $(wildcard $(AUDIT_DIR)/*.cpp))

# Object
DRIVER_OBJ = driver.o
DISTORM_OBJ = $(DISTORM_DIR)/distorm3.a
PT_OBJ = $(patsubst %.c, %.o, $(PT_SCR))
TAINT_OBJ = $(patsubst %.cpp, %.o, $(TAINT_SCR))
REDIS_OBJ = $(patsubst %.cpp, %.o, $(REDIS_SCR))
AUDIT_OBJ = $(patsubst %.cpp, %.o, $(AUDIT_SCR))
OBJ = $(DRIVER_OBJ) $(TAINT_OBJ) $(PT_OBJ) $(DISTORM_OBJ) $(REDIS_OBJ) $(AUDIT_OBJ) $(HIREDIS_SO)

# Option (debug/progress)
export VER = normal
ifeq ($(VER), debug)
	OPT += -O0 -g -DDEBUG
else
	OPT += -O3
endif

# Compile
CPP = g++
WARNINGS = -Wall -Wextra
CXXFLAGS  = $(WARNINGS) $(OPT)

# Target
TARGET = driver

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CPP) $(CXXFLAGS) $(DISTORM_INC) $^ -lz -o $@ $(LIBS)

$(DRIVER_OBJ): driver.cpp
	$(CPP) $(CXXFLAGS) $(DISTORM_INC) -c $<

$(TAINT_OBJ): %.o:%.cpp
	(cd $(TAINT_DIR) && $(MAKE) $(TAINT_OBJ))

$(REDIS_OBJ): %.o:%.cpp
	(cd $(REDIS_DIR) && $(MAKE) $(REDIS_OBJ))

$(AUDIT_OBJ): %.o:%.cpp
	(cd $(AUDIT_DIR) && $(MAKE) $(AUDIT_OBJ))

$(PT_OBJ): %.o:%.c
	(cd $(PT_DIR) && $(MAKE) $(PT_OBJ))

$(DISTORM_OBJ):
	make -C $(DISTORM_DIR)/make/linux

.PHONY: clean

clean:
	rm -f *.o *.a $(TARGET)
	(cd $(TAINT_DIR) && $(MAKE) clean)
	(cd $(REDIS_DIR) && $(MAKE) clean)
	(cd $(AUDIT_DIR) && $(MAKE) clean)
	(cd $(PT_DIR) && $(MAKE) clean)
