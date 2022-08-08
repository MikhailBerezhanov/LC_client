# May be redefined while calling
# 	make PROTOC=...
PROTOC = protoc
CXX = g++

PROTOFILES = lc.proto log.proto log_result.proto info.proto push.proto
SRC_DIR = ../src/proto

all:
	@if test ! -d $(SRC_DIR); then mkdir $(SRC_DIR); fi
	@$(PROTOC) -I./ --cpp_out=$(SRC_DIR) $(PROTOFILES)
	@./rename.sh $(SRC_DIR) .cc .cpp;

test:	
	@$(CXX) -Wall -I$(SRC_DIR) $(SRC_DIR)/lc.pb.cpp $(SRC_DIR)/log.pb.cpp $(SRC_DIR)/log_result.pb.cpp proto_test.cpp -o ptest.out -lprotobuf -lpthread
