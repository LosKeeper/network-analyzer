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
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/arp.cap -v 0
	@echo "------------------------------------"
	@echo "Testing DHCP..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/dhcp.cap -v 0
	@echo "------------------------------------"
	@echo "Testing DHCP/IPV6..."
	./$(BINDIR)/$(TARGET) -o test/dhcpv6.cap -v 0
	@echo "------------------------------------"
	@echo "Testing HTTP..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/http.cap -v 0
	@echo "------------------------------------"
	@echo "Testing SMTP..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/smtp.cap -v 0
	@echo "------------------------------------"
	@echo "Testing FTP..."
	@echo "------------------------------------"
	./$(BINDIR)/$(TARGET) -o test/ftp.cap -v 0
	@echo "------------------------------------"

.PHONY: clean cov
clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(OBJDIR)/*.gcda
	rm -f $(OBJDIR)/*.gcno
	rm -f $(BINDIR)/$(TARGET)