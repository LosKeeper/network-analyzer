# Analyseur Réseau 
[![version](https://img.shields.io/badge/version-0.1.5-blue.svg)](https://github.com/LosKeeper/analyseur-reseau)
[![compiler](https://img.shields.io/badge/compiler-g++-red.svg)](https://github.com/LosKeeper/jeu-echecs-cpp/blob/main/Makefile)
[![license](https://img.shields.io/badge/license-GPL_3.0-yellow.svg)](https://github.com/LosKeeper/analyseur-reseau/blob/main/LICENSE)
[![author](https://img.shields.io/badge/author-LosKeeper-blue)](https://github.com/LosKeeper)
> This is a network analyzer that can be used to analyze the network traffic of a computer. It is written in C and uses the libpcap library to capture the packets.

# Table of Contents
1. [Compilation](#compilation)
2. [Usage](#usage)
3. [Examples](#examples)
4. [To do](#to-do)


## Compilation
To execute the program, you must first compile it using the command `make`. This will create an executable file called `sniffer` in the `bin` folder.

## Usage
To use the programm, you must run the executable file `sniffer` with the following arguments:
* `-i` or `--interface` followed by the name of the interface to capture the packets from.
* `-o` or `--origin`    followed by the file name to sniffer the packets from.
* `-f` or `--filter`    followed by the filter to apply to the packets.
* `-v` or `--verbose`   followed by `0` or `1` or `2` to display more infos in the terminal.
* `-h` or `--help`      to display the help.

## Examples
* `./sniffer -i eth0 -f "port 80"`: Capture the packets from the interface `eth0` and apply the filter `port 80`.
* `./sniffer -o capture.pcap -f "port 80"`: Capture the packets from the file `capture.pcap` and apply the filter `port 80`.
* `./sniffer -i eth0 -f "port 80" -v 1`: Capture the packets from the interface `eth0` and apply the filter `port 80` and display more infos in the terminal.

## To do
- [x] Load infos from a file.
- [x] Read BOOTP/DHCP packets.
- [x] Decode vendor infos in DHCP packets.
- [x] Verbose mode.
- [x] Decode SMTP packets.
- [ ] Print correctly the vendor infos.
- [ ] Deocde DNS packets.
- [x] Decode HTTP packets.
- [ ] Decode POP3 packets.
- [ ] Decode IMAP packets.
- [x] Decode FTP packets.
- [ ] Decode ICMP packets.
- [x] Decode ARP packets.
- [x] Decode Telnet packets.
- [ ] IPv6 support.