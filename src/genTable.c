#include "../include/secp256k1.h"
#include "util.h"
#include "scalar.h"
#include "group.h"
#include "ecmult_gen.h"
#include "hash_impl.h"
#include "table.h"
#include "time.h"
#include "field_5x52_impl.h"
#include "group_impl.h"
#include <stdio.h>
#include <stdlib.h>

int main(){
    int i, xIn, yIn;
    unsigned char *x = (unsigned char*) malloc(sizeof(unsigned char)*32);
    unsigned char *y = (unsigned char*) malloc(sizeof(unsigned char)*32);
    secp256k1_gej r;
    secp256k1_ge t;
    secp256k1_fe fx,fy;
    unsigned char kb[32] = {
        0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
        0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
        0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
        0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
    };
    clock_t start,finish;
    double total_time, average_time;
    start = clock();
    for(i = 0; i < 32;i++){
        xIn = ((int)kb[i] << 1) + 512*i;
		yIn = xIn + 1;
        x = T[xIn];
        y = T[yIn];
        secp256k1_fe_set_b32(&fx,x);
        secp256k1_fe_set_b32(&fy,y);
        secp256k1_ge_set_xy(&t,&fx,&fy);
        secp256k1_gej_add_ge(&r, &r, &t);
    }
    finish = clock();
    total_time = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("total time %f seconds\n", total_time);
}