CC=g++
CFLAGS=-std=c++11 -o
LIBS=-lcurl -lssl -lcrypto
SRC=main.cpp
OUT=attestation_client

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(OUT) $(SRC) $(LIBS)

clean:
	rm -f $(OUT)