CC=g++
CFLAGS=-c -g -Wall
LDFLAGS=-lcrypto
SOURCES=main.cpp proxy.cpp router.cpp mysocket.cpp aes-test.cpp
OBJECTS=$(SOURCES:.cpp=.o)

HW1=projc
$(HW1):$(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@
%.o: %.cpp
	$(CC) $(CFLAGS) $< -o $@
		     
clean:
	rm $(OBJECTS)
	rm $(HW1)
