LDLIBS=-lpcap

all: send-arp-test


main.o: GetMac.h GetIp.h mac.h ip.h ethhdr.h arphdr.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

GetMac.o: GetMac.h GetMac.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

GetIp.o: GetIp.h GetIp.cpp

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o GetMac.o GetIp.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
