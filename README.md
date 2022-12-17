# Analyseur Réseau 
[![version](https://img.shields.io/badge/version-1.0.1-blue.svg)](https://github.com/LosKeeper/analyseur-reseau)
[![compiler](https://img.shields.io/badge/compiler-g++-red.svg)](https://github.com/LosKeeper/analyseur-reseau/blob/main/Makefile)
[![license](https://img.shields.io/badge/license-GPL_3.0-yellow.svg)](https://github.com/LosKeeper/analyseur-reseau/blob/main/LICENSE)
[![author](https://img.shields.io/badge/author-LosKeeper-blue)](https://github.com/LosKeeper)
> This is a network analyzer that can be used to analyze the network traffic of a computer. It is written in C and uses the libpcap library to capture the packets.

# Table of Contents
1. [Compilation](#compilation)
2. [Usage](#usage)
3. [Examples](#examples)


## Compilation
To execute the program, you must first compile it using the command `make`. This will create an executable file called `sniffer` in the `bin` folder.
You can also use the command `make test` to compile the program and test it whith the files in the `test` folder.

## Usage
To use the programm, you must run the executable file `sniffer` with the following arguments:
* `-i` followed by the name of the interface to capture the packets from.
* `-o` followed by the file name to sniffer the packets from.
* ~~`-f` followed by the filter to apply to the packets.~~ (not implemented yet)
* `-v` followed by `0` or `1` or `2` to display more infos in the terminal.
* `-h` to display the help.

## Examples
* `./sniffer -i eth0`: Capture the packets from the interface `eth0`.
  * **Note:** You must run the program with `sudo` if you want to capture the packets from an interface.
* `./sniffer -o capture.pcap`: Capture the packets from the file `capture.pcap`.
* `./sniffer -i eth0 -v 1`: Capture the packets from the interface `eth0` and display more infos in the terminal.

