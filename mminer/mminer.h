#ifndef MMINER_H
#define MMINER_H

#include <stddef.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <sys/time.h>
#include <cmath>

#include <gmp.h>
#include <signal.h>
#include <getopt.h>
#include "cuda_helper.h"

#define DEBUG 0

#if DEBUG

#define DEFAULT_ADDRESS "0xbb5e958846f2e246faa3bccbba89f10c37ac3996";
#define DEFAULT_LASTMINED "0x0";
#define DEFAULT_DIFFICULTY "0x7a2aff56698420"

#else

#define DEFAULT_ADDRESS "0xE8946EC499a839c72E60bA7d437E28cd73a3f487";
#define DEFAULT_LASTMINED "0x422000000003B0019000000";
#define DEFAULT_DIFFICULTY "5731203885580"

#endif

#define R 1088
#define B 1600
#define W 64
#define C 512
#define DATA_BLOCK_SIZE (R / W)
#define BLOCK_SIZE (B / W)
#define HASH_SIZE (C / 2 / 8)
#define Nr 24
#define SUFFIX 0x01

#if DEBUG
#define BLOCKNUM 2
#define BLOCKX (2)
#else
#define BLOCKNUM 30000
#define BLOCKX (128)
#endif

#define STREAMNUM 5

#define BLOCKSIZE (DATA_BLOCK_SIZE * 8)
#define SUMDATASIZE (BLOCKSIZE * BLOCKNUM * BLOCKX)

typedef struct OPTS
{
    char *str_address;
    char *str_lastMined;
    char *str_difficulty;
    uint64_t upper_difficulty;
    uint64_t lower_difficulty;
    char *str_startNonce;
    uint64_t startNonce;
    int device;
    bool test;
} OPTS;

#endif