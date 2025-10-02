BINARY=crypto

all: build

build:
	go build -o $(BINARY) main.go

install: build
	cp $(BINARY) /usr/local/bin/

clean:
	rm -f $(BINARY)
