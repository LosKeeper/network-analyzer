CC ?= gcc
CFLAGS ?= -g -O0 -ggdb -Wall -Wextra -Werror 
LDLIBS ?=-lpcap

INCLUDE_PATH = ./lib

TARGET   = sniffer

SRCDIR   = src
OBJDIR   = obj
BINDIR   = bin

SOURCES  := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(INCLUDE_PATH)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

$(BINDIR)/$(TARGET): $(OBJECTS)
	mkdir -p $(BINDIR)
	$(CC) -o $@ $^ $(CFLAGS) $(LDLIBS)
	@echo "Linking complete!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c $(INCLUDES)
	mkdir -p $(OBJDIR)
	$(CC) -o $@ -c $< $(CFLAGS) -isystem$(INCLUDE_PATH)

test: $(BINDIR)/$(TARGET)
	@echo "Running tests..." 
	@echo "Testing ARP..."
	@echo "Verbose level 0..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/arp.cap -v 0
	@echo "------------------------------------"
	@echo "Verbose level 1..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/arp.cap -v 1
	@echo "------------------------------------"
	@echo "Verbose level 2..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/arp.cap -v 2
	@echo "------------------------------------"
	@echo "Testing DHCP..."
	@echo "Verbose level 0..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/dhcp.cap -v 0
	@echo "------------------------------------"
	@echo "Verbose level 1..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/dhcp.cap -v 1
	@echo "------------------------------------"
	@echo "Verbose level 2..."
	@echo "------------------------------------"
	@echo "Testing SMTP/IPV6..."
	@echo "Verbose level 0..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/smtpv6.cap -v 0
	@echo "------------------------------------"
	@echo "Verbose level 1..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/smtpv6.cap -v 1
	@echo "------------------------------------"
	@echo "Verbose level 2..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/smtpv6.cap -v 2
	@echo "------------------------------------"
	@echo "Testing HTTP..."
	@echo "Verbose level 0..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/http.cap -v 0
	@echo "------------------------------------"
	@echo "Verbose level 1..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/http.cap -v 1
	@echo "------------------------------------"
	@echo "Verbose level 2..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/http.cap -v 2
	@echo "------------------------------------"
	@echo "Testing SMTP..."
	@echo "Verbose level 0..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/smtp.cap -v 0
	@echo "------------------------------------"
	@echo "Verbose level 1..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/smtp.cap -v 1
	@echo "------------------------------------"
	@echo "Verbose level 2..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/smtp.cap -v 2
	@echo "------------------------------------"
	@echo "Testing FTP..."
	@echo "Verbose level 0..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/ftp.cap -v 0
	@echo "------------------------------------"
	@echo "Verbose level 1..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/ftp.cap -v 1
	@echo "------------------------------------"
	@echo "Verbose level 2..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/ftp.cap -v 2
	@echo "------------------------------------"
	@echo "Testing DNS..."
	@echo "Verbose level 0..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/dns_qa.cap -v 0
	@echo "------------------------------------"
	@echo "Verbose level 1..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/dns_qa.cap -v 1
	@echo "------------------------------------"
	@echo "Verbose level 2..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/dns_qa.cap -v 2
	@echo "------------------------------------"
	@echo "Testing TELNET..."
	@echo "Verbose level 0..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/telnet.cap -v 0
	@echo "------------------------------------"
	@echo "Verbose level 1..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/telnet.cap -v 1
	@echo "------------------------------------"
	@echo "Verbose level 2..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/telnet.cap -v 2
	@echo "------------------------------------"

tar:
	make clean
	tar -cvf $(TARGET).tar *

.PHONY: clean cov
clean:
	rm -f *.tar
	rm -f $(OBJDIR)/*.o
	rm -f $(OBJDIR)/*.gcda
	rm -f $(OBJDIR)/*.gcno
	rm -f $(BINDIR)/$(TARGET)