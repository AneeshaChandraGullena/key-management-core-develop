#!/bin/bash

go tool cover -func=cover.out | grep "total:" | awk '{ print $3 }' | sed 's/[][()><%]/ /g' > cover_percent.out

COVERAGE=$(<cover_percent.out)

echo "-------------------------------------------------------------------------"
echo "COVERAGE IS ${COVERAGE}%"
echo "-------------------------------------------------------------------------"
