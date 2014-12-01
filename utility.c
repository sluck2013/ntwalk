#include "utility.h"
#include "stdarg.h"

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

void prtErr(const char *errMsg) {
    prtln("ERROR: %s", errMsg);
    fflush(stdout);
}

void errExit(const char *errMsg) {
    prtErr(errMsg);
    exit(1);
}
