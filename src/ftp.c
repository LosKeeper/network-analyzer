#include "ftp.h"

int got_ftp(u_char *args, const u_char *packet, int req) {
    print_verbosity(*args, 0, "FTP\t\t\t\t");
    if (req) {
        print_verbosity(*args, 0, "Request -> ");
    } else {
        print_verbosity(*args, 0, "Response -> ");
    }
    // Print the type of the resquest
    if (strncmp((char *)packet, "USER", 4) == 0) {
        print_verbosity(*args, 0, "USER : ");
        int i = 5;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "PASS", 4) == 0) {
        print_verbosity(*args, 0, "PASS : ");
        int i = 5;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "ACCT", 4) == 0) {
        print_verbosity(*args, 0, "ACCT");
        return 1;
    } else if (strncmp((char *)packet, "CWD", 3) == 0) {
        print_verbosity(*args, 0, "CWD : ");
        int i = 4;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "CDUP", 4) == 0) {
        print_verbosity(*args, 0, "CDUP");
        return 1;
    } else if (strncmp((char *)packet, "SMNT", 4) == 0) {
        print_verbosity(*args, 0, "SMNT");
        return 1;
    } else if (strncmp((char *)packet, "REIN", 4) == 0) {
        print_verbosity(*args, 0, "REIN");
        return 1;
    } else if (strncmp((char *)packet, "QUIT", 4) == 0) {
        print_verbosity(*args, 0, "QUIT");
        return 1;
    } else if (strncmp((char *)packet, "PORT", 4) == 0) {
        print_verbosity(*args, 0, "PORT");
        return 1;
    } else if (strncmp((char *)packet, "PASV", 4) == 0) {
        print_verbosity(*args, 0, "PASV");
        return 1;
    } else if (strncmp((char *)packet, "TYPE", 4) == 0) {
        print_verbosity(*args, 0, "TYPE");
        return 1;
    } else if (strncmp((char *)packet, "STRU", 4) == 0) {
        print_verbosity(*args, 0, "STRU");
        return 1;
    } else if (strncmp((char *)packet, "RETR", 4) == 0) {
        print_verbosity(*args, 0, "RETR : ");
        int i = 5;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "FEAT", 4) == 0) {
        print_verbosity(*args, 0, "FEAT");
        return 1;
    } else if (strncmp((char *)packet, "MODE", 4) == 0) {
        print_verbosity(*args, 0, "MODE");
        return 1;
    } else if (strncmp((char *)packet, "STOR", 4) == 0) {
        print_verbosity(*args, 0, "STOR : ");
        int i = 5;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "STOU", 4) == 0) {
        print_verbosity(*args, 0, "STOU");
        return 1;
    } else if (strncmp((char *)packet, "APPE", 4) == 0) {
        print_verbosity(*args, 0, "APPE");
        return 1;
    } else if (strncmp((char *)packet, "ALLO", 4) == 0) {
        print_verbosity(*args, 0, "ALLO");
        return 1;
    } else if (strncmp((char *)packet, "REST", 4) == 0) {
        print_verbosity(*args, 0, "REST");
        return 1;
    } else if (strncmp((char *)packet, "RNFR", 4) == 0) {
        print_verbosity(*args, 0, "RNFR");
        return 1;
    } else if (strncmp((char *)packet, "RNTO", 4) == 0) {
        print_verbosity(*args, 0, "RNTO");
        return 1;
    } else if (strncmp((char *)packet, "ABOR", 4) == 0) {
        print_verbosity(*args, 0, "ABOR");
        return 1;
    } else if (strncmp((char *)packet, "DELE", 4) == 0) {
        print_verbosity(*args, 0, "DELE");
        return 1;
    } else if (strncmp((char *)packet, "RMD", 3) == 0) {
        print_verbosity(*args, 0, "RMD");
        return 1;
    } else if (strncmp((char *)packet, "MKD", 3) == 0) {
        print_verbosity(*args, 0, "MKD");
        return 1;
    } else if (strncmp((char *)packet, "PWD", 3) == 0) {
        print_verbosity(*args, 0, "PWD");
        return 1;
    } else if (strncmp((char *)packet, "LIST", 4) == 0) {
        print_verbosity(*args, 0, "LIST");
        return 1;
    } else if (strncmp((char *)packet, "NLST", 4) == 0) {
        print_verbosity(*args, 0, "NLST");
        return 1;
    } else if (strncmp((char *)packet, "SITE", 4) == 0) {
        print_verbosity(*args, 0, "SITE");
        return 1;
    } else if (strncmp((char *)packet, "SYST", 4) == 0) {
        print_verbosity(*args, 0, "SYST");
        return 1;
    } else if (strncmp((char *)packet, "STAT", 4) == 0) {
        print_verbosity(*args, 0, "STAT");
        return 1;
    } else if (strncmp((char *)packet, "HELP", 4) == 0) {
        print_verbosity(*args, 0, "HELP");
        return 1;
    } else if (strncmp((char *)packet, "NOOP", 4) == 0) {
        print_verbosity(*args, 0, "NOOP");
        return 1;
    } else if (strncmp((char *)packet, "AUTH", 4) == 0) {
        print_verbosity(*args, 0, "AUTH");
        return 1;
    } else if (strncmp((char *)packet, "CCC", 3) == 0) {
        print_verbosity(*args, 0, "CCC");
        return 1;
    } else if (strncmp((char *)packet, "CONF", 4) == 0) {
        print_verbosity(*args, 0, "CONF");
        return 1;
    } else if (strncmp((char *)packet, "ENC", 3) == 0) {
        print_verbosity(*args, 0, "ENC");
        return 1;
    } else if (strncmp((char *)packet, "MIC", 3) == 0) {
        print_verbosity(*args, 0, "MIC");
        return 1;
    } else if (strncmp((char *)packet, "PBSZ", 4) == 0) {
        print_verbosity(*args, 0, "PBSZ");
        return 1;
    } else if (strncmp((char *)packet, "PROT", 4) == 0) {
        print_verbosity(*args, 0, "PROT");
        return 1;
    } else if (strncmp((char *)packet, "ADAT", 4) == 0) {
        print_verbosity(*args, 0, "ADAT");
        return 1;
    } else if (strncmp((char *)packet, "MLSD", 4) == 0) {
        print_verbosity(*args, 0, "MLSD");
        return 1;
    } else if (strncmp((char *)packet, "MLST", 4) == 0) {
        print_verbosity(*args, 0, "MLST");
        return 1;
    } else if (strncmp((char *)packet, "OPTS", 4) == 0) {
        print_verbosity(*args, 0, "OPTS");
        return 1;
    } else if (strncmp((char *)packet, "EPRT", 4) == 0) {
        print_verbosity(*args, 0, "EPRT");
        return 1;
    } else if (strncmp((char *)packet, "EPSV", 4) == 0) {
        print_verbosity(*args, 0, "EPSV");
        return 1;
    } else if (strncmp((char *)packet, "MDTM", 4) == 0) {
        print_verbosity(*args, 0, "MDTM");
        return 1;
    } else if (strncmp((char *)packet, "SIZE", 4) == 0) {
        print_verbosity(*args, 0, "SIZE : ");
        int i = 5;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "CLNT", 4) == 0) {
        print_verbosity(*args, 0, "CLNT : ");
        int i = 5;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "150", 3) == 0) {
        int i = 0;
        while (isprint(packet[i]) && packet[i] != ';') {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        // Get the port for the data connection
        i = 0;
        int port = 0;
        char port_str[5];
        while (packet[i] != ':') {
            i++;
        }
        i++;
        int j = 0;
        while (packet[i] != ';') {
            port_str[j] = packet[i];
            i++;
            j++;
        }
        port_str[j] = '\0';
        port = atoi(port_str);
        return port;

    } else if (strncmp((char *)packet, "331", 3) == 0) {
        print_verbosity(*args, 0, "Password required");
        return 1;
    } else if (strncmp((char *)packet, "230", 3) == 0) {
        print_verbosity(*args, 0, "Login successful");
        return 1;
    } else if (strncmp((char *)packet, "215", 3) == 0) {
        print_verbosity(*args, 0, "System type : ");
        int i = 4;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "220", 3) == 0) {
        print_verbosity(*args, 0, "Welcome message : ");
        int i = 4;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "221", 3) == 0) {
        print_verbosity(*args, 0, "Goodbye message : ");
        int i = 4;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "211", 3) == 0) {
        int i = 4;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "250", 3) == 0) {
        print_verbosity(*args, 0, "Command successful");
        return 1;
    } else if (strncmp((char *)packet, "200", 3) == 0) {
        print_verbosity(*args, 0, "Noted");
        return 1;
    } else if (strncmp((char *)packet, "257", 3) == 0) {
        int i = 4;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    } else if (strncmp((char *)packet, "227", 3) == 0) {
        print_verbosity(*args, 0, "Entering passive mode");
        return 1;
    } else if (strncmp((char *)packet, "213", 3) == 0) {
        print_verbosity(*args, 0, "File size : ");
        int i = 4;
        while (isprint(packet[i])) {
            print_verbosity(*args, 0, "%c", packet[i]);
            i++;
        }
        return 1;
    }
    return 0;
}

int got_ftp_data(u_char *args, const u_char *packet) {
    (void)packet;
    print_verbosity(*args, 0, "FTP-DATA\t\t\t");
    return 0;
}