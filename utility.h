#ifndef UTILITY_H
#define UTILITY_H

#include <stdlib.h>
#include <stdio.h>

int prtln(const char* format, ...);
void sprtMac(char* dest, const unsigned char* mac);
void prtErr(const char* msg);
void errExit(const char* msg);

#endif
