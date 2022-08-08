# Using compiler from environmental settings
#CC = gcc
#CXX = g++
#CC = arm-buildroot-linux-gnueabihf-gcc
#CXX = arm-buildroot-linux-gnueabihf-g++

# Protobuf compiler (use system protoc by default) 
PROTOC = protoc

CFLAGS = -O2
CXXFLAGS = -O2 -std=c++11 -Wall -Wno-psabi

MAIN_DIR = .
BIN_NAME = lcc.out

# App version
MAJOR = 0
MINOR = 1
VERSION = $(MAJOR).$(MINOR)

BIN_DIR = $(MAIN_DIR)/bin
OBJ_DIR = $(MAIN_DIR)/obj
TEST_DIR = $(MAIN_DIR)/tests
SRC_DIR = $(MAIN_DIR)/src

SRCS_DIRS = $(SRC_DIR) \
			$(SRC_DIR)/proto \
			$(SRC_DIR)/logger/cpp_src \

# Search source files in specified directories 
search_wildcards = $(addsuffix /*.cpp, $(SRCS_DIRS))

# Path for templates to search source files in directories list
VPATH = $(SRCS_DIRS)

OBJS = $(addprefix $(OBJ_DIR)/, $(notdir $(patsubst %.cpp, %.o, $(wildcard $(search_wildcards)))))

INCLUDE_PREFIX = -I
INCLUDES = $(addprefix $(INCLUDE_PREFIX), $(SRCS_DIRS))

LIBS_INC_PREFIX = -L
LIBS =
LIBS_INC = $(addprefix $(LIBS_INC_PREFIX ), $(LIBS))

LINK_LIBS = -lcurl -luuid -lpthread -lsqlite3 -lcrypto -lprotobuf
	
#DEFINE_PREFIX = -D   
DEFINES = -D_LC_CLIENT_TEST

.PHONY: clean clean-proto clean-all info

# Main target
all: prep info bin 

proto-src:
	@if test ! -d $(SRC_DIR)/proto; then cd $(MAIN_DIR)/proto && make PROTOC=$(PROTOC); fi

# Prepare directories for output
prep:
	@if test ! -d $(BIN_DIR); then mkdir $(BIN_DIR); fi
	@if test ! -d $(OBJ_DIR); then mkdir $(OBJ_DIR); fi
	@if test ! -d $(TEST_DIR); then mkdir $(TEST_DIR); fi

info:
	@echo "Using compiler: $(notdir $(CXX))"

# Start compiler for different files
# $@, $<, $^  -  Automatic Variables
# $@	-	the name of the target being generated
# $<	-	the first prerequisite (usually a source file)
# $^	-	the names of all the prerequisites, with spaces between them
# $(@F)	-	The file-within-directory part of the file name of the target
# https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html#Automatic-Variables
$(OBJ_DIR)/%.o : %.cpp
	@echo "\033[32m>\033[0m CXX compile: \t" $<" >>> "$@
	@$(CXX) -c $(CXXFLAGS) $(INCLUDES) $(DEFINES) $< -o $(@)  

# Start linker
bin:$(OBJS)
	@echo "Linking binary file: '$(BIN_NAME)' with $(shell $(CXX) --version | head -1)"
	@$(CXX) -o $(BIN_DIR)/$(BIN_NAME) $^ $(LINK_LIBS)
	@echo "\033[32mBuild finished [$(shell date +"%T")]\033[0m"

clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR) 

clean-proto:
	@rm -rf $(SRC_DIR)/proto

clean-all: clean clean-proto

# ------------------------------ Tests rules section ------------------------------

protocol-test-bin: TEST_BIN = $(TEST_DIR)/protocol_LC.test
protocol-test-bin: DEFINES = -D_LC_PROTOCOL_TEST
protocol-test-bin: $(addprefix $(OBJ_DIR)/, logger.o lc_utils.o lc_protocol.o)
	@echo "\033[32m>\033[0m linking unit test: $(TEST_BIN)"
	@$(CXX) -o $(TEST_BIN) $^ -lcrypto
protocol-test: prep protocol-test-bin

# SysEvents storaging as DB files module
sys_db-test-bin: TEST_BIN = $(TEST_DIR)/sys_ev_LC.test
sys_db-test-bin: DEFINES = -D_LC_SYS_EV_TEST
sys_db-test-bin: $(addprefix $(OBJ_DIR)/, logger.o lc_utils.o lc_sys_ev.o lc_sys_db.o)
	@echo "\033[32m>\033[0m linking unit test: $(TEST_BIN)"
	@$(CXX) -o $(TEST_BIN) $^ -luuid -lsqlite3 -lcrypto 
sys_db-test: prep sys_db-test-bin

# Transactions and SysEvents storaging as proto binary module
trans-test-bin: TEST_BIN = $(TEST_DIR)/trans_LC.test
trans-test-bin: DEFINES = -D_LC_TRANS_TEST
trans-test-bin: $(addprefix $(OBJ_DIR)/, logger.o lc.pb.o log.pb.o log_result.pb.o lc_utils.o lc_sys_ev.o lc_trans.o)
	@echo "\033[32m>\033[0m linking unit test: $(TEST_BIN)"
	@$(CXX) -o $(TEST_BIN) $^ -lprotobuf -lpthread -lcrypto
trans-test: prep trans-test-bin

# Client in debug mode
client-test-bin: TEST_BIN = $(TEST_DIR)/client_LC.test
client-test-bin: DEFINES = -D_LC_CLIENT_TEST
client-test-bin: CXXFLAGS += -g	-O0
client-test-bin: $(addprefix $(OBJ_DIR)/, logger.o lc_utils.o lc_protocol.o lc.pb.o log.pb.o log_result.pb.o lc_sys_ev.o lc_trans.o lc_client.o)
	@echo "\033[32m>\033[0m linking unit test: $(TEST_BIN)"
	@$(CXX) -o $(TEST_BIN) $^ -lcurl -luuid -lprotobuf -lpthread -lcrypto
client-test: prep client-test-bin

# Memory check rule
mem_check: TARGET_NAME = $(TEST_DIR)/client_LC.test.
mem_check: OUTPUT_FILE = $(TEST_DIR)/valout.txt
mem_check: client-test
	@valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --log-file=$(OUTPUT_FILE) $(TARGET_NAME)
	@cat $(OUTPUT_FILE) | less