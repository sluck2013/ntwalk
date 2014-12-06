#ifndef UTILITY_H
#define UTILITY_H

#include <stdlib.h>
#include <stdio.h>

int prtln(const char* format, ...);
int prt(const char* format, ...);
void sprtMac(char* dest, const unsigned char* mac);
void parseIP(unsigned char *dest, const char *src);
void sprtIP(char* dest, const unsigned char *src);
void prtErr(const char* msg);
void errExit(const char* msg);

#endif
