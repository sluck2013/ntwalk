#include "utility.h"
#include "stdarg.h"
#include "string.h"
#include "constants.h"

/*
 * print formatted data to stdout and start a new line
 * @return same as printf()
 * @param same as printf()
 */
int prtln(const char* format, ...) {
    va_list arg;
    va_start(arg, format);
    int n = vprintf(format, arg);
    va_end(arg);
    printf("\n");
#ifdef DEBUG
    fflush(stdout);
#endif
    return n;
}

/*
 * print MAC address into string buffer
 * @param dest pointer to destination string buffer
 * @param mac pointer to buffer storing MAC address to be printed
 */
void sprtMac(char* dest, const unsigned char* mac) {
    for (int i = 0; i < 5; ++i) {
        sprintf(dest + i * 3, "%.2x:", mac[i]);
    }
    sprintf(dest + 15, "%.2x", mac[5]);
}

void sprtIP(char* dest, const unsigned char *src) {
    dest[0] = '\0';
    for (int i = 0; i < IP_LEN; ++i) {
        char seg[5];
        if (i > 0) {
            sprintf(seg, ".%d", src[i]);
        } else {
            sprintf(seg, "%d", src[i]);
        }
        strcat(dest, seg);
    }
}

void parseIP(unsigned char *dest, const char *src) {
    char src2[IP_STR_LEN];
    strcpy(src2, src);
    char* p = strtok(src2, ".");
    dest[0] = atoi(p);
    for (int i = 1; i < 4; ++i) {
        p = strtok(NULL, ".");
        dest[i] = atoi(p);
    }
}


void prtErr(const char *errMsg) {
    prtln("ERROR: %s", errMsg);
    fflush(stdout);
}

void errExit(const char *errMsg) {
    prtErr(errMsg);
    exit(1);
}
