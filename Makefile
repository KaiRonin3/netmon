CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -O2
LDFLAGS = -lpcap
TARGET  = netmon
SRCS    = main.c capture.c parser.c flow.c analysis.c

.PHONY: all clean

all:
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)