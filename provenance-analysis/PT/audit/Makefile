# Path
AUDIT_DIR = $(shell pwd)

# Scr
AUDIT_SCR = $(filter-out $(AUDIT_DIR)/driver.cpp, $(wildcard $(AUDIT_DIR)/*.cpp))

# Lib
JSON_LIB = -ljsoncpp
LIBS = $(strip $(JSON_LIB))

# Object
AUDIT_OBJ = $(patsubst %.cpp, %.o, $(AUDIT_SCR))
DRIVER_OBJ = $(AUDIT_DIR)/driver.o

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

all: $(AUDIT_OBJ) $(TARGET)

$(TARGET): $(AUDIT_OBJ) $(DRIVER_OBJ)
	$(CPP) $(CXXFLAGS) $^ -o $@ $(LIBS)

$(AUDIT_OBJ):%.o : %.cpp
	$(CPP) $(CXXFLAGS) -c $<

.PHONY: clean

clean:
	rm -f *.o *.a $(TARGET)
