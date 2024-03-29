#include "telnet.h"

int got_telnet(u_char *args, const u_char *packet, int data_len) {
    int rtn = 0;

    // Verbosity 0
    print_verbosity(*args, 0, "TELNET\t\t\t\t");

    // Verbosity 1
    print_verbosity(*args, 1, "\033[32m");
    print_verbosity(*args, 1, "TELNET : ");
    print_verbosity(*args, 1, "\033[0m");

    // Verbosity 2
    print_verbosity(*args, 2, "\033[32m");
    print_verbosity(*args, 2, "TELNET : ");
    print_verbosity(*args, 2, "\033[0m");

    // Get the negotiation
    while (packet[0] == 0xFF) {

        if (rtn == 0) {
            rtn = 1;
        }

        switch (*args) {
        case 0:
            print_verbosity(*args, 0, "IAC");
            goto end_telnet;
        default:
            print_verbosity(*args, 1, "IAC -> ");
            print_verbosity(*args, 2, "IAC -> ");
            // Print the type of the negotiation
            switch (packet[1]) {
            case 0xFD:
                print_verbosity(*args, 1, "DO");
                print_verbosity(*args, 2, "DO");
                break;

            case 0xFE:
                print_verbosity(*args, 1, "DONT");
                print_verbosity(*args, 2, "DONT");
                break;

            case 0xFB:
                print_verbosity(*args, 1, "WILL");
                print_verbosity(*args, 2, "WILL");
                break;

            case 0xFC:
                print_verbosity(*args, 1, "WONT");
                print_verbosity(*args, 2, "WONT");
                break;

            case 0xFA:
                print_verbosity(*args, 1, "SB");
                print_verbosity(*args, 2, "SB");
                break;

            case 0xF0:
                print_verbosity(*args, 1, "SE");
                print_verbosity(*args, 2, "SE");
                break;
            }
            // Print the option
            switch (packet[2]) {
            case 0x01:
                print_verbosity(*args, 1, " ECHO");
                print_verbosity(*args, 2, " ECHO");
                break;

            case 0x03:
                print_verbosity(*args, 1, " SUPPRESS-GO-AHEAD");
                print_verbosity(*args, 2, " SUPPRESS-GO-AHEAD");
                break;

            case 0x05:
                print_verbosity(*args, 1, " STATUS");
                print_verbosity(*args, 2, " STATUS");
                break;

            case 0x18:
                print_verbosity(*args, 1, " TERMINAL-TYPE");
                print_verbosity(*args, 2, " TERMINAL-TYPE");
                break;

            case 0x1F:
                print_verbosity(*args, 1, " NAWS");
                print_verbosity(*args, 2, " NAWS");
                break;

            case 0x20:
                print_verbosity(*args, 1, " TERMINAL-SPEED");
                print_verbosity(*args, 2, " TERMINAL-SPEED");
                break;

            case 0x21:
                print_verbosity(*args, 1, " REMOTE-FLOW-CONTROL");
                print_verbosity(*args, 2, " REMOTE-FLOW-CONTROL");
                break;

            case 0x22:
                print_verbosity(*args, 1, " LINEMODE");
                print_verbosity(*args, 2, " LINEMODE");
                break;

            case 0x23:
                print_verbosity(*args, 1, " X-DISPLAY-LOCATION");
                print_verbosity(*args, 2, " X-DISPLAY-LOCATION");
                break;

            case 0x24:
                print_verbosity(*args, 1, " ENVIRON");
                print_verbosity(*args, 2, " ENVIRON");
                break;

            case 0x25:
                print_verbosity(*args, 1, " AUTHENTICATION");
                print_verbosity(*args, 2, " AUTHENTICATION");
                break;

            case 0x26:
                print_verbosity(*args, 1, " ENCRYPTION");
                print_verbosity(*args, 2, " ENCRYPTION");
                break;

            case 0x27:
                print_verbosity(*args, 1, " NEW-ENVIRON");
                print_verbosity(*args, 2, " NEW-ENVIRON");
                break;

            case 0x2B:
                print_verbosity(*args, 1, " CHARSET");
                print_verbosity(*args, 2, " CHARSET");
                break;

            case 0x2C:
                print_verbosity(*args, 1, " RSP");
                print_verbosity(*args, 2, " RSP");
                break;

            case 0x2D:
                print_verbosity(*args, 1, " COM-PORT-OPTION");
                print_verbosity(*args, 2, " COM-PORT-OPTION");
                break;

            case 0x2E:
                print_verbosity(*args, 1, " SUPPRESS-LOCAL-ECHO");
                print_verbosity(*args, 2, " SUPPRESS-LOCAL-ECHO");
                break;

            case 0x2F:
                print_verbosity(*args, 1, " STARTTLS");
                print_verbosity(*args, 2, " STARTTLS");
                break;

            case 0x30:
                print_verbosity(*args, 1, " KERMIT");
                print_verbosity(*args, 2, " KERMIT");
                break;

            case 0x31:
                print_verbosity(*args, 1, " SEND-URL");
                print_verbosity(*args, 2, " SEND-URL");
                break;

            case 0x32:
                print_verbosity(*args, 1, " FORWARD-X");
                print_verbosity(*args, 2, " FORWARD-X");
                break;

            case 0x33:
                print_verbosity(*args, 1, " PRAGMA-LOGON");
                print_verbosity(*args, 2, " PRAGMA-LOGON");
                break;

            case 0x34:
                print_verbosity(*args, 1, " SSPI-LOGON");
                print_verbosity(*args, 2, " SSPI-LOGON");
                break;

            case 0x35:
                print_verbosity(*args, 1, " PRAGMA-HEARTBEAT");
                print_verbosity(*args, 2, " PRAGMA-HEARTBEAT");
                break;

            case 0x36:
                print_verbosity(*args, 1, " EXOPL");
                print_verbosity(*args, 2, " EXOPL");
                break;

            case 0x37:
                print_verbosity(*args, 1, " TELNET-ASCII");
                print_verbosity(*args, 2, " TELNET-ASCII");
                break;

            case 0x38:
                print_verbosity(*args, 1, " TELNET-3270");
                print_verbosity(*args, 2, " TELNET-3270");
                break;

            case 0x39:
                print_verbosity(*args, 1, " TELNET-EC");
                print_verbosity(*args, 2, " TELNET-EC");
                break;

            case 0x3A:
                print_verbosity(*args, 1, " TELNET-NEW-ENVIRON");
                print_verbosity(*args, 2, " TELNET-NEW-ENVIRON");
                break;

            case 0x3B:
                print_verbosity(*args, 1, " TELNET-CHARSET");
                print_verbosity(*args, 2, " TELNET-CHARSET");
                break;

            case 0x3C:
                print_verbosity(*args, 1, " TELNET-REMOTE-PROC");
                print_verbosity(*args, 2, " TELNET-REMOTE-PROC");
                break;

            case 0x3D:
                print_verbosity(*args, 1, " TELNET-ENCODING");
                print_verbosity(*args, 2, " TELNET-ENCODING");
                break;

            case 0x3E:
                print_verbosity(*args, 1, " TELNET-NAWS");
                print_verbosity(*args, 2, " TELNET-NAWS");
                break;

            case 0x3F:
                print_verbosity(*args, 1, " TELNET-TTYPE");
                print_verbosity(*args, 2, " TELNET-TTYPE");
                break;

            case 0x40:
                print_verbosity(*args, 1, " TELNET-3270-REGIME");
                print_verbosity(*args, 2, " TELNET-3270-REGIME");
                break;

            case 0x41:
                print_verbosity(*args, 1, " TELNET-X.3-PAD");
                print_verbosity(*args, 2, " TELNET-X.3-PAD");
                break;

            case 0x42:
                print_verbosity(*args, 1, " TELNET-NAWS");
                print_verbosity(*args, 2, " TELNET-NAWS");
                break;
            }
        }
        packet += 3;
        print_verbosity(*args, 1, "\n");
        print_verbosity(*args, 2, "\n");
    }
    // Verbose 0
    if (isprint(packet[0])) {
        print_verbosity(*args, 0, "Data");
        rtn = 1;
    }

    // Verbose 1 and 2
    print_verbosity(*args, 1, "Data -> ");
    print_verbosity(*args, 2, "Data -> ");
    if (isprint(packet[0])) {
        rtn = 1;
        int offset = 0;
        while (isprint(packet[offset]) && offset < data_len) {
            print_verbosity(*args, 1, "%c", packet[offset]);
            print_verbosity(*args, 2, "%c", packet[offset]);
            offset++;
        }
        print_verbosity(*args, 1, "\0");
        print_verbosity(*args, 2, "\0");
    }
    print_verbosity(*args, 1, "\n");
    print_verbosity(*args, 2, "\n");

end_telnet:;
    return rtn;
}