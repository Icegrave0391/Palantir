# target
TARGET = driverbeat

# dir
SRC_DIR = $(shell pwd)
PROJ_DIR = $(shell dirname $(SRC_DIR))
LIB_DIR = $(PROJ_DIR)/lib/lib
INC_DIR = $(PROJ_DIR)/lib/include
DB_DIR = $(SRC_DIR)/db
PARSER_DIR = $(SRC_DIR)/parser
UTIL_DIR = $(SRC_DIR)/util
BEAT_DIR = $(PARSER_DIR)/beat

# src (Todo: polish graphviz)
DB_SRC = $(wildcard $(DB_DIR)/*.cpp)
PARSER_SRC = $(wildcard $(PARSER_DIR)/*.cpp)
UTIL_SRC = $(filter-out $(UTIL_DIR)/graphviz.cpp, $(wildcard $(UTIL_DIR)/*.cpp))
BEAT_SRC = $(wildcard $(BEAT_DIR)/*.cpp)
DRIVERBEAT_SRC = $(SRC_DIR)/driverbeat.cpp
DRIVERDAR_SRC = $(SRC_DIR)/driverdar.cpp

# obj
DB_OBJ = $(patsubst %.cpp, %.o, $(DB_SRC))
UTIL_OBJ = $(patsubst %.cpp, %.o, $(UTIL_SRC))
PARSER_OBJ = $(patsubst %.cpp, %.o, $(PARSER_SRC))
BEAT_OBJ = $(patsubst %.cpp, %.o, $(BEAT_SRC))
OBJS = $(DB_OBJ) $(UTIL_OBJ) $(PARSER_OBJ)
BEAT_OBJS = $(OBJS) $(BEAT_OBJ)
DRIVERBEAT_OBJ = $(patsubst %.cpp, %.o, $(DRIVERBEAT_SRC))
DRIVERDAR_OBJ = $(patsubst %.cpp, %.o, $(DRIVERDAR_SRC))

# Option (debug/progress)
export OPT = -std=c++17 
VER = normal
ifeq ($(VER), debug)
	OPT += -O0 -g -DDEBUG
else
	OPT += -O3
endif
# display progress bar for KG Construction
ifeq ($(BAR),1)
	OPT += -DBAR
endif

# Path
export INC_PATH = -I$(INC_DIR) -I$(SRC_DIR)
NEO4J_PATH = $(shell pkg-config neo4j-client --cflags)
JSONCPP_PATH =  $(shell pkg-config jsoncpp --cflags)
LIB_PATH = -L$(LIB_DIR)

# Libs
NEO4J_LIB = $(shell pkg-config neo4j-client --libs)
CONFIG_LIB = -lconfig++
POSTGRESQL_LIB = -lpqxx -lpq
JSON_LIB = -ljsoncpp
THREAD_LIB = -pthread
GRAPHVIZ_LIB = -lgvc
LIBS += $(LIB_PATH) $(strip $(NEO4J_LIB) $(CONFIG_LIB) $(POSTGRESQL_LIB) $(JSON_LIB) $(THREAD_LIB))

# Compile
CC = g++
WARNINGS = -Wall -Wextra
CXXFLAGS  = $(WARNINGS) $(OPT)

all: $(TARGET)

driverbeat: $(DRIVERBEAT_OBJ) $(BEAT_OBJS)
	$(CC) $(CXXFLAGS) $^ -o $@ $(LIBS) $(INC_PATH)

$(DRIVERDAR_OBJ): $(DRIVERDAR_SRC)
	$(CC) $(CXXFLAGS) -c $< $(INC_PATH) $(NEO4J_PATH) $(JSONCPP_PATH)

$(DRIVERBEAT_OBJ): $(DRIVERBEAT_SRC)
	$(CC) $(CXXFLAGS) -c $< $(INC_PATH) $(NEO4J_PATH) $(JSONCPP_PATH)

$(DB_OBJ): %.o:%.cpp
	(cd $(DB_DIR) && $(MAKE) all)

$(UTIL_OBJ): %.o:%.cpp
	(cd $(UTIL_DIR) && $(MAKE) all)

$(PARSER_OBJ): %.o:%.cpp
	(cd $(PARSER_DIR) && $(MAKE) $(PARSER_OBJ))

$(BEAT_OBJ): %.o:%.cpp
	(cd $(PARSER_DIR) && $(MAKE) $(BEAT_OBJ))

.PHONY: clean

clean:
	rm -f *.o *.a $(TARGET)
	(cd $(UTIL_DIR) && $(MAKE) clean)
	(cd $(DB_DIR) && $(MAKE) clean)
	(cd $(PARSER_DIR) && $(MAKE) clean)
