#!/usr/bin/env bash
# © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

# must be in the project base directory (i.e key-management-core)
# execute with the following: scripts/genProtoc.sh

protoc -I=protoBufferV3/ --go_out=plugins=grpc:protoBufferV3 protoBufferV3/keyManagement.proto
