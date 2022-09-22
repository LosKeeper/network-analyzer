# Analyseur Réseau
`This is a network analyzer that can be used to analyze the network traffic of a computer. It is written in C and uses the libpcap library to capture the packets.`

## Compilation
To execute the program, you must first compile it using the command `make`. This will create an executable file called `sniffer` in the `bin` folder.

## Usage
To use the programm, you must run the executable file `sniffer` with the following arguments:
* `-i` or `--interface` followed by the name of the interface to capture the packets from.
* `-o` or `--origin`    followed by the file name to sniffer the packets from.
* `-f` or `--filter`    followed by the filter to apply to the packets.
* `-v` or `--verbose`   followed by `1` or `2` or `3` to display more infos in the terminal.
* `-h` or `--help`      to display the help.

## Examples
* `./sniffer -i eth0 -f "port 80"`: Capture the packets from the interface `eth0` and apply the filter `port 80`.
* `./sniffer -o capture.pcap -f "port 80"`: Capture the packets from the file `capture.pcap` and apply the filter `port 80`.
* `./sniffer -i eth0 -f "port 80" -v 1`: Capture the packets from the interface `eth0` and apply the filter `port 80` and display more infos in the terminal.

## To do
- [ ] Load infos from a file.
- [ ] Read BOOTP/DHCP packets.