#!/bin/bash

# Function to print blue text
print_blue() {
    echo -e "\e[94m$1\e[0m"
}

print_blue "Running javascript tests..."
cd js
npx mocha --require esm test.mjs
cd ..

print_blue "Running python tests..."
cd python
python3 -m unittest test.py
cd ..

print_blue "Running golang tests..."
cd golang_cli
go mod download
go test -v -count=1 ./...

