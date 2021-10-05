#ifndef MMINER_H
#define MMINER_H

#include <stddef.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <cmath>

#include <gmp.h>
#include <signal.h>
#include <sstream>
#include <fstream>
#include "cuda_helper.h"

#ifdef __linux__
	#include <sys/time.h>
	#include <getopt.h>
#elif _WIN32
	#include "getopt.h"
	#include <Windows.h>
	#include <stdint.h> // portable: uint64_t   MSVC: __int64 
	int gettimeofday(struct timeval* tp, struct timezone* tzp)
	{
		// Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
		// This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
		// until 00:00:00 January 1, 1970 
		static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

		SYSTEMTIME  system_time;
		FILETIME    file_time;
		uint64_t    time;

		GetSystemTime(&system_time);
		SystemTimeToFileTime(&system_time, &file_time);
		time = ((uint64_t)file_time.dwLowDateTime);
		time += ((uint64_t)file_time.dwHighDateTime) << 32;

		tp->tv_sec = (long)((time - EPOCH) / 10000000L);
		tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
		return 0;
	}
#endif

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
	char *nonce_directory;
    bool test;
} OPTS;

#endif