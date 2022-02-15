//
//  CSOps.c
//  CSOps

/**
* Copyright (C) 2012 Yogesh Prem Swami. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/


#include <unistd.h>		// getpid()
#include <stdio.h>		// printf() etc
#include <stdlib.h>		// atoi()
#include <string.h>		// strlen()
#include <errno.h>		// strerror()
#include "codesign.h"		// csops() and additional flags
#include <sys/syslimits.h>	// PATH_MAX
#include <CommonCrypto/CommonDigest.h>	// SHA_HASH_LENGTH. Gratutous? Yes!
#import <Foundation/Foundation.h>

#define MAX_CSOPS_BUFFER_LEN 3*PATH_MAX     // 3K < 1 page

static char BUFFER[512000];

typedef void (^describe_t)(void);
static pid_t process_id;

static struct csops_struct{
    describe_t    describe; // These are the things that make blocks shine
    unsigned int ops;
    void*     useraddr;
    size_t     usersize;
}CSOPS[] = {
    /* Get the entitlement blob. */
    {
        .ops          = CS_OPS_ENTITLEMENTS_BLOB,
        .useraddr      = (void*)BUFFER,
        .usersize      = (512000)
    }
};


#define CSOPS_SIZE (sizeof(CSOPS)/sizeof(CSOPS[0]))

char* parse_plist( char* plist_string){
    NSString* plistString = [NSString stringWithUTF8String:plist_string];
    NSData* plistData = [plistString dataUsingEncoding:NSUTF8StringEncoding];
    NSPropertyListFormat* format;
    NSString* error;
    NSDictionary* plist = [NSPropertyListSerialization propertyListWithData:plistData options:NSPropertyListImmutable format:&format error:&error];
    NSData * jsonData = [NSJSONSerialization  dataWithJSONObject:plist options:0 error:&error];
    NSString * myString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    return [myString UTF8String];
}

void* exec_csops( int proc_id){
    int result;
    struct csops_struct* cs;
    memset(BUFFER, 0, 512000);
    cs = &CSOPS[0];
    process_id = proc_id;
    result = csops(process_id, cs->ops, cs->useraddr, cs->usersize);
    if (result < 0) {
        printf("%s\n", strerror(errno));
    }else{
        if (  ((char*)(cs->useraddr))[0] != 0x00 ){
            printf("%s\n", parse_plist( ((char*)(cs->useraddr)) + 8 ));
        }else{
            printf("No Entitlements");
        }
    }
}


static void usage(int argc, const char* const argvp[]){

	fprintf(stderr, "Usage: %s PID\n", argvp[0]);
}

int exec_csops_status( int proc_id){
    int result;
    int i;
    struct csops_struct* cs;
    uint32_t int_buffer;
    cs = &CSOPS[0];
    process_id = proc_id;
    result = csops(process_id, CS_OPS_STATUS, (void*)&int_buffer, sizeof(int_buffer));

    if (result < 0) {
        return -1;
    }else{
        return int_buffer;
    }
}

int main (int argc, const char * argv[])
{
	int i;

	if (argc < 2) {
		usage(argc, argv);
		return -1;
	}

	/* The last argument is the process ID. */
	process_id = atoi(argv[argc-1]);

	if (process_id < 0 ) {
		fprintf(stderr, "Invalid process id: %s\n", argv[argc-1]);
		usage(argc, argv);
		return -1;
	}
    printf("Entitlements:\n");
	exec_csops(process_id);
    printf("\nCode sign flags: ");
    int codesign = exec_csops_status(process_id);
    printf("0x%02x\n", codesign);
	return 0;
}
