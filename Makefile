all: wireview

wireview: cpp/wireview.cpp
	g++ -o wireview cpp/wireview.cpp -lpcap

.PHONY: clean

clean:
	rm -f wireview *.o
