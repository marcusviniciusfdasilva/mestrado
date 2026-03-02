// Copyright (c) 2025 Marcus Vinicius F. da Silva
// SPDX-License-Identifier: MIT

#if defined(D_NEXYS_A7) 
#include <bsp_printf.h> 
#include <bsp_mem_map.h> 
#include <bsp_version.h> 
#else 
PRE_COMPILED_MSG("no platform was defined") 
#endif 
#include <psp_api.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h> 

// XADC
#define ADR_XADC                0x80001080
#define DATA_XADC               0x80001084
#define STATUS_XADC             0x80001088
#define CRTL_XADC               0x8000108C
#define TESTE_XADC              0x80001090
#define RW_XADC                 0x80001094
 
// ChaCha20 
#define NAME_CHACHA_0           0x80003000 
#define NAME_CHACHA_1           0x80003004 
#define VERSION_CHACHA          0x80003008 
 
#define CTRL_CHACHA             0x8000300c 
#define STATUS_CHACHA           0x80003010 
#define KEYLEN_CHACHA           0x80003014 
#define ROUNDS_CHACHA           0x80003018 
#define COUNTER_CHACHA          0x8000301c 
 
#define KEY_CHACHA_0            0x800030c0 
#define KEY_CHACHA_1            0x800030c4 
#define KEY_CHACHA_2            0x800030c8 
#define KEY_CHACHA_3            0x800030cc 
#define KEY_CHACHA_4            0x800030d0 
#define KEY_CHACHA_5            0x800030d4 
#define KEY_CHACHA_6            0x800030d8 
#define KEY_CHACHA_7            0x800030dc

#define IV_CHACHA_0             0x80003024
#define IV_CHACHA_1             0x80003028
#define IV_CHACHA_2             0x8000302c

#define DATA_IN_CHACHA_0        0x80003030
#define DATA_IN_CHACHA_1        0x80003034
#define DATA_IN_CHACHA_2        0x80003038
#define DATA_IN_CHACHA_3        0x8000303c
#define DATA_IN_CHACHA_4        0x80003040
#define DATA_IN_CHACHA_5        0x80003044
#define DATA_IN_CHACHA_6        0x80003048
#define DATA_IN_CHACHA_7        0x8000304c
#define DATA_IN_CHACHA_8        0x80003050
#define DATA_IN_CHACHA_9        0x80003054
#define DATA_IN_CHACHA_10       0x80003058
#define DATA_IN_CHACHA_11       0x8000305c
#define DATA_IN_CHACHA_12       0x80003060
#define DATA_IN_CHACHA_13       0x80003064
#define DATA_IN_CHACHA_14       0x80003068
#define DATA_IN_CHACHA_15       0x8000306c

#define DATA_OUT_CHACHA_0       0x80003080
#define DATA_OUT_CHACHA_1       0x80003084
#define DATA_OUT_CHACHA_2       0x80003088
#define DATA_OUT_CHACHA_3       0x8000308c
#define DATA_OUT_CHACHA_4       0x80003090
#define DATA_OUT_CHACHA_5       0x80003094
#define DATA_OUT_CHACHA_6       0x80003098
#define DATA_OUT_CHACHA_7       0x8000309c
#define DATA_OUT_CHACHA_8       0x800030a0
#define DATA_OUT_CHACHA_9       0x800030a4
#define DATA_OUT_CHACHA_10      0x800030a8
#define DATA_OUT_CHACHA_11      0x800030ac
#define DATA_OUT_CHACHA_12      0x800030b0
#define DATA_OUT_CHACHA_13      0x800030b4
#define DATA_OUT_CHACHA_14      0x800030b8
#define DATA_OUT_CHACHA_15      0x800030bc

#define DATA_CHIFRA_CHACHA_0    0x80003100
#define DATA_CHIFRA_CHACHA_1    0x80003104
#define DATA_CHIFRA_CHACHA_2    0x80003108   
#define DATA_CHIFRA_CHACHA_3    0x8000310c   
#define DATA_CHIFRA_CHACHA_4    0x80003110   
#define DATA_CHIFRA_CHACHA_5    0x80003114   
#define DATA_CHIFRA_CHACHA_6    0x80003118   
#define DATA_CHIFRA_CHACHA_7    0x8000311c   
#define DATA_CHIFRA_CHACHA_8    0x80003120 
#define DATA_CHIFRA_CHACHA_9    0x80003124 
#define DATA_CHIFRA_CHACHA_10   0x80003128 
#define DATA_CHIFRA_CHACHA_11   0x8000312c 
#define DATA_CHIFRA_CHACHA_12   0x80003130 
#define DATA_CHIFRA_CHACHA_13   0x80003134 
#define DATA_CHIFRA_CHACHA_14   0x80003138 
#define DATA_CHIFRA_CHACHA_15   0x8000313c 

//Poly1305 
#define NAME_POLY_0     0x80003200 
#define NAME_POLY_1     0x80003204 
#define VERSION_POLY    0x80003208 
 
#define CTRL_POLY       0x80003210 
#define STATUS_POLY     0x80003214 
 
#define BLOCKLEN_POLY   0x80003218 
 
#define KEY_POLY_0      0x80003220 
#define KEY_POLY_1      0x80003224 
#define KEY_POLY_2      0x80003228 
#define KEY_POLY_3      0x8000322c 
#define KEY_POLY_4      0x80003230 
#define KEY_POLY_5      0x80003234 
#define KEY_POLY_6      0x80003238 
#define KEY_POLY_7      0x8000323c 
 
#define BLOCK_POLY_0    0x80003240 
#define BLOCK_POLY_1    0x80003244 
#define BLOCK_POLY_2    0x80003248 
#define BLOCK_POLY_3    0x8000324c 
 
#define MAC_POLY_0      0x80003250 
#define MAC_POLY_1      0x80003254 
#define MAC_POLY_2      0x80003258 
#define MAC_POLY_3      0x8000325c 

//Display 7-Seg
#define SegEn_ADDR    0x80001038
#define SegDig_ADDR   0x8000103C

#define DELAY 10000000

#define READ_WB(dir) (*(volatile unsigned *)dir) 
#define WRITE_WB(dir, value) { (*(volatile unsigned *)dir) = (value); } 

void    chacha20 (  const int key_len,  
                    const int numb_rounds, 
                    const int count_init_val, 
                    const int k[8], 
                    const int N[3], 
                    const int data[16], 
                    int dout[],
                    int chifra[]) 
{ 

    int i=1,s; 

    //control variables 
    int init=0x01, 
        next=0x02;
 
    //keylen to 256bit 
    WRITE_WB(KEYLEN_CHACHA,key_len); 
 
    // number of rounds to 20 
    WRITE_WB(ROUNDS_CHACHA,numb_rounds); 
 
    // set up the counter 
    WRITE_WB(COUNTER_CHACHA, count_init_val); 
 
    // set the key 
    WRITE_WB(KEY_CHACHA_0,k[0]); 
    WRITE_WB(KEY_CHACHA_1,k[1]); 
    WRITE_WB(KEY_CHACHA_2,k[2]); 
    WRITE_WB(KEY_CHACHA_3,k[3]); 
    WRITE_WB(KEY_CHACHA_4,k[4]); 
    WRITE_WB(KEY_CHACHA_5,k[5]); 
    WRITE_WB(KEY_CHACHA_6,k[6]); 
    WRITE_WB(KEY_CHACHA_7,k[7]); 
 
    // set the nonce 
    WRITE_WB(IV_CHACHA_0,N[0]); 
    WRITE_WB(IV_CHACHA_1,N[1]); 
    WRITE_WB(IV_CHACHA_2,N[2]); 

 
    // data to chacha 
    WRITE_WB(DATA_IN_CHACHA_0, data[0] ); 
    WRITE_WB(DATA_IN_CHACHA_1, data[1] ); 
    WRITE_WB(DATA_IN_CHACHA_2, data[2] ); 
    WRITE_WB(DATA_IN_CHACHA_3, data[3] ); 
    WRITE_WB(DATA_IN_CHACHA_4, data[4] ); 
    WRITE_WB(DATA_IN_CHACHA_5, data[5] ); 
    WRITE_WB(DATA_IN_CHACHA_6, data[6] ); 
    WRITE_WB(DATA_IN_CHACHA_7, data[7] ); 
    WRITE_WB(DATA_IN_CHACHA_8, data[8] ); 
    WRITE_WB(DATA_IN_CHACHA_9, data[9] ); 
    WRITE_WB(DATA_IN_CHACHA_10,data[10]); 
    WRITE_WB(DATA_IN_CHACHA_11,data[11]); 
    WRITE_WB(DATA_IN_CHACHA_12,data[12]); 
    WRITE_WB(DATA_IN_CHACHA_13,data[13]); 
    WRITE_WB(DATA_IN_CHACHA_14,data[14]); 
    WRITE_WB(DATA_IN_CHACHA_15,data[15]); 
     
    //control variables 
    WRITE_WB(CTRL_CHACHA, init ); 
 
    int wait=1; 
    int estado=0x00; 
 
    while (wait==1) { 
        estado=READ_WB(STATUS_CHACHA); 
        if (estado!=0x00){ 
            wait=0; 
        } 
    } 

    chifra[0]  = READ_WB(DATA_CHIFRA_CHACHA_0); 
    chifra[1]  = READ_WB(DATA_CHIFRA_CHACHA_1); 
    chifra[2]  = READ_WB(DATA_CHIFRA_CHACHA_2); 
    chifra[3]  = READ_WB(DATA_CHIFRA_CHACHA_3); 
    chifra[4]  = READ_WB(DATA_CHIFRA_CHACHA_4); 
    chifra[5]  = READ_WB(DATA_CHIFRA_CHACHA_5); 
    chifra[6]  = READ_WB(DATA_CHIFRA_CHACHA_6); 
    chifra[7]  = READ_WB(DATA_CHIFRA_CHACHA_7); 
    chifra[8]  = READ_WB(DATA_CHIFRA_CHACHA_8); 
    chifra[9]  = READ_WB(DATA_CHIFRA_CHACHA_9); 
    chifra[10] = READ_WB(DATA_CHIFRA_CHACHA_10); 
    chifra[11] = READ_WB(DATA_CHIFRA_CHACHA_11); 
    chifra[12] = READ_WB(DATA_CHIFRA_CHACHA_12); 
    chifra[13] = READ_WB(DATA_CHIFRA_CHACHA_13); 
    chifra[14] = READ_WB(DATA_CHIFRA_CHACHA_14); 
    chifra[15] = READ_WB(DATA_CHIFRA_CHACHA_15); 


    dout[0]  = READ_WB(DATA_OUT_CHACHA_0); 
    dout[1]  = READ_WB(DATA_OUT_CHACHA_1); 
    dout[2]  = READ_WB(DATA_OUT_CHACHA_2); 
    dout[3]  = READ_WB(DATA_OUT_CHACHA_3); 
    dout[4]  = READ_WB(DATA_OUT_CHACHA_4); 
    dout[5]  = READ_WB(DATA_OUT_CHACHA_5); 
    dout[6]  = READ_WB(DATA_OUT_CHACHA_6); 
    dout[7]  = READ_WB(DATA_OUT_CHACHA_7); 
    dout[8]  = READ_WB(DATA_OUT_CHACHA_8); 
    dout[9]  = READ_WB(DATA_OUT_CHACHA_9); 
    dout[10] = READ_WB(DATA_OUT_CHACHA_10); 
    dout[11] = READ_WB(DATA_OUT_CHACHA_11); 
    dout[12] = READ_WB(DATA_OUT_CHACHA_12); 
    dout[13] = READ_WB(DATA_OUT_CHACHA_13); 
    dout[14] = READ_WB(DATA_OUT_CHACHA_14); 
    dout[15] = READ_WB(DATA_OUT_CHACHA_15); 

    //return(dout[0],dout[1],dout[2],dout[3],dout[4],dout[5],dout[6],dout[7],dout[8],dout[9],dout[10],dout[11],dout[12],dout[13],dout[14],dout[15],chifra[0],chifra[1],chifra[2],chifra[3],chifra[4],chifra[5],chifra[6],chifra[7],chifra[8],chifra[9],chifra[10],chifra[11],chifra[12],chifra[13],chifra[14],chifra[15]); 
    
   } 

void    poly1305 (  const int block_len,
                    const int message_length,
                    const int k[8],  
                    const int data[],  
                    int mac[4]) 
{ 

    //POLY1305 CONTROL SIGNALS 
    const int INIT_POLY = 0x01; 
    const int NEXT_POLY = 0x02; 
    const int FINISH_POLY = 0x04; 

    //POLY1305 STATUS COMPARISON SIGNALS 
    const int READY_POLY = 0x01;

    //POLY1305 START

    //write the key 
    WRITE_WB(KEY_POLY_0,k[0]); 
    WRITE_WB(KEY_POLY_1,k[1]); 
    WRITE_WB(KEY_POLY_2,k[2]); 
    WRITE_WB(KEY_POLY_3,k[3]);
    WRITE_WB(KEY_POLY_4,k[4]); 
    WRITE_WB(KEY_POLY_5,k[5]); 
    WRITE_WB(KEY_POLY_6,k[6]); 
    WRITE_WB(KEY_POLY_7,k[7]); 

    //printfNexys("key poly:");
    //printfNexys("%X %X %X %X\n%X %X %X %X\n",k[0],k[1],k[2],k[3],k[4],k[5],k[6],k[7]);
    
    //send block clear 
    WRITE_WB(BLOCK_POLY_0,0x00); 
    WRITE_WB(BLOCK_POLY_1,0x00); 
    WRITE_WB(BLOCK_POLY_2,0x00); 
    WRITE_WB(BLOCK_POLY_3,0x00);

    //send an INIT value to CTRL 
    WRITE_WB(CTRL_POLY,INIT_POLY);

    //wait for ready status 
    int s = 0x01; 
    while (s == READY_POLY){ 
        s = READ_WB(STATUS_POLY);  
    } 

    //POLY1305 SEND DATA
    for (int j = 0; j < message_length/4; j += 4) {

        // enviar os 128 bits (4 palavras de 32 bits)
        WRITE_WB(BLOCK_POLY_0, data[j + 0]);
        WRITE_WB(BLOCK_POLY_1, data[j + 1]);
        WRITE_WB(BLOCK_POLY_2, data[j + 2]);
        WRITE_WB(BLOCK_POLY_3, data[j + 3]);

        if (j >= ((message_length/4)-4)){
            switch (((message_length/4) % 4))
            {
            case 0:
                //printfNexys("falta 0\n");
                break;
            case 3:
                //printfNexys("falta 1\n");
                WRITE_WB(BLOCK_POLY_3, 0x00);
                break;
            case 2:
                WRITE_WB(BLOCK_POLY_2, 0x00);
                WRITE_WB(BLOCK_POLY_3, 0x00);
                //printfNexys("falta 2\n");
                break;
            case 1:
                WRITE_WB(BLOCK_POLY_1, 0x00);
                WRITE_WB(BLOCK_POLY_2, 0x00);
                WRITE_WB(BLOCK_POLY_3, 0x00);
                //printfNexys("falta 3\n");
                break;
            }
        }
        
        
        //printfNexys("AEAD %d\n",j); 
        //printfNexys("%X %X  %X  %X : ",data[j + 0],data[j + 1],data[j + 2],data[j + 3]);

        //send the block len information 
        WRITE_WB(BLOCKLEN_POLY,block_len); 
        
        //send a NEXT value to CTRL 
        WRITE_WB(CTRL_POLY,NEXT_POLY);

        //wait for ready status 
        s = 0x01; 
        while (s == READY_POLY){ 
            s = READ_WB(STATUS_POLY); 
        }
    }

    //send a FINISH value to CTRL 
    WRITE_WB(CTRL_POLY,FINISH_POLY); 
    
    //wait for ready status 
    s = 0x01; 
    while (s == READY_POLY) { 
        s = READ_WB(STATUS_POLY); 
        //printfNexys("FINISH:\n");  
    } 

    //read the generated MAC 
    mac[0] = READ_WB(MAC_POLY_0); 
    mac[1] = READ_WB(MAC_POLY_1); 
    mac[2] = READ_WB(MAC_POLY_2); 
    mac[3] = READ_WB(MAC_POLY_3);

}

void AEAD_chacha20_poly1305_send(const int key[8], 
                                 const int iv[3], 
                                 const int AAD[3], 
                                 const int aad_length, 
                                 const int data[],
                                 const int data_length,
                                 int encrypted[],
                                 int tag[4])
{

    const int encrypted_length = data_length;
    int data_zero[16] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    int dout[16];
    int chifra[16];

    int val_temp = ((data_length + 15) / 16) * 16;
    int encrypted_temp[val_temp];

    val_temp = (((encrypted_length + 15) / 16) * 16)-encrypted_length;
    int encrypted_miss = val_temp;

    val_temp = 16 - aad_length;
    int aad_miss = val_temp;

    int aad_LE;
    int encrypted_LE;

    int key_poly[8];

    const int key_len = 0x01;
    const int numb_rounds = 0x14;
    const int block_len = 0x10;

    chacha20(key_len,numb_rounds,0x00,key,iv,data_zero,dout,chifra);

    key_poly[0] = chifra[0];
    key_poly[1] = chifra[1];
    key_poly[2] = chifra[2];
    key_poly[3] = chifra[3];
    key_poly[4] = chifra[4];
    key_poly[5] = chifra[5];
    key_poly[6] = chifra[6];
    key_poly[7] = chifra[7];

    //printfNexys("key poly:");
    //printfNexys("%X %X %X %X\n%X %X %X %X\n",key_poly[0],key_poly[1],key_poly[2],key_poly[3],key_poly[4],key_poly[5],key_poly[6],key_poly[7]);

    for ( int counter = 1; counter < data_length/4; counter += 16)
    {
        chacha20(key_len,numb_rounds,1+(counter/16),key,iv,data+(counter-1),dout,chifra);

        encrypted_temp[counter - 1] = dout[0];
        encrypted_temp[counter + 0] = dout[1];
        encrypted_temp[counter + 1] = dout[2];
        encrypted_temp[counter + 2] = dout[3];
        encrypted_temp[counter + 3] = dout[4];
        encrypted_temp[counter + 4] = dout[5];
        encrypted_temp[counter + 5] = dout[6];
        encrypted_temp[counter + 6] = dout[7];
        encrypted_temp[counter + 7] = dout[8];
        encrypted_temp[counter + 8] = dout[9];
        encrypted_temp[counter + 9] = dout[10];
        encrypted_temp[counter + 10] = dout[11];
        encrypted_temp[counter + 11] = dout[12];
        encrypted_temp[counter + 12] = dout[13];
        encrypted_temp[counter + 13] = dout[14];
        encrypted_temp[counter + 14] = dout[15];

        /*printfNexys("Encrypted bloco dout:"); 
        printfNexys("%X %X  %X  %X", dout[0], dout[1], dout[2], dout[3]);
        printfNexys("%X %X  %X  %X", dout[4], dout[5], dout[6], dout[7]);
        printfNexys("%X %X  %X  %X", dout[8], dout[9], dout[10], dout[11]);
        printfNexys("%X %X  %X  %X", dout[12], dout[13], dout[14], dout[15]);*/

    }

    switch ((4 - (encrypted_length % 4)) % 4)
    {
    case 1:
        encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] & 0xFFFFFF00;
        //encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] >> 8;
        break;
    case 2:
        encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] & 0xFFFF0000;
        //encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] >> 16;
        break;
    case 3:
        encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] & 0xFF000000;
        //encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] >> 24;
        break;
    
    default:
        break;
    }
    memcpy(encrypted, encrypted_temp, data_length+((((encrypted_length + 3) / 4) * 4) - encrypted_length));

    /*printfNexys("Encrypted:");
    printfNexys("Bloco 1:");  
    printfNexys("%X %X  %X  %X", encrypted[0], encrypted[1], encrypted[2], encrypted[3]);
    printfNexys("%X %X  %X  %X", encrypted[4], encrypted[5], encrypted[6], encrypted[7]);
    printfNexys("%X %X  %X  %X", encrypted[8], encrypted[9], encrypted[10], encrypted[11]);
    printfNexys("%X %X  %X  %X", encrypted[12], encrypted[13], encrypted[14], encrypted[15]);
    printfNexys("Bloco 2:"); 
    printfNexys("%X %X  %X  %X", encrypted[16], encrypted[17], encrypted[18], encrypted[19]);
    printfNexys("%X %X  %X  %X", encrypted[20], encrypted[21], encrypted[22], encrypted[23]);
    printfNexys("%X %X  %X  %X", encrypted[24], encrypted[25], encrypted[26], encrypted[27]);
    printfNexys("%X %X  %X  %X", encrypted[28], encrypted[29], encrypted[30], encrypted[31]);*/
    
    aad_LE = converter_int_para_little_endian(aad_length);
    encrypted_LE = converter_int_para_little_endian(encrypted_length);

    //printfNexys("aad_LE: %X", aad_LE);
    //printfNexys("encrypted_LE: %X", encrypted_LE);

    int AEAD[(aad_length + aad_miss + encrypted_length + encrypted_miss + 16)/4];
    memset(AEAD, 0, sizeof(AEAD));

    for (size_t i = 0; i < aad_length/4; i++)
    {
        AEAD[i]=AAD[i];
    }
    for (size_t i = 0; i < (encrypted_length+3)/4; i++)
    {
        AEAD[i+aad_length/4+aad_miss/4]=encrypted[i];
    }
    AEAD[(aad_length+aad_miss+encrypted_length+encrypted_miss)/4]=aad_LE;
    AEAD[(aad_length+aad_miss+encrypted_length+encrypted_miss)/4+2]=encrypted_LE;

    /*
    printfNexys("AEAD:"); 
    printfNexys("%X %X  %X  %X", AEAD[0], AEAD[1], AEAD[2], AEAD[3]);
    printfNexys("%X %X  %X  %X", AEAD[4], AEAD[5], AEAD[6], AEAD[7]);
    printfNexys("%X %X  %X  %X", AEAD[8], AEAD[9], AEAD[10], AEAD[11]);
    printfNexys("%X %X  %X  %X", AEAD[12], AEAD[13], AEAD[14], AEAD[15]);
    printfNexys("%X %X  %X  %X", AEAD[16], AEAD[17], AEAD[18], AEAD[19]);
    printfNexys("%X %X  %X  %X", AEAD[20], AEAD[21], AEAD[22], AEAD[23]);
    printfNexys("%X %X  %X  %X", AEAD[24], AEAD[25], AEAD[26], AEAD[27]);
    printfNexys("%X %X  %X  %X", AEAD[28], AEAD[29], AEAD[30], AEAD[31]);
    printfNexys("%X %X  %X  %X", AEAD[32], AEAD[33], AEAD[34], AEAD[35]);
    printfNexys("%X %X  %X  %X", AEAD[36], AEAD[37], AEAD[38], AEAD[39]);
    */

    poly1305(block_len,sizeof(AEAD),key_poly,AEAD,tag);

}

int AEAD_chacha20_poly1305_receive(const int key[8], 
                                    const int iv[3], 
                                    const int AAD[3], 
                                    const int aad_length, 
                                    const int encrypted[],
                                    const int encrypted_length,
                                    int data[],
                                    const int tag[4])
{

    int mac[4] = {0};

    const int data_length = encrypted_length;
    int data_zero[16] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    int dout[16];
    int chifra[16];

    int val_temp = ((data_length + 15) / 16) * 16;
    int encrypted_temp[val_temp];

    val_temp = (((encrypted_length + 15) / 16) * 16)-encrypted_length;
    int encrypted_miss = val_temp;

    val_temp = 16 - aad_length;
    int aad_miss = val_temp;

    int aad_LE;
    int encrypted_LE;

    int key_poly[8];

    const int key_len = 0x01;
    const int numb_rounds = 0x14;
    const int block_len = 0x10;

    chacha20(key_len,numb_rounds,0x00,key,iv,data_zero,dout,chifra);

    key_poly[0] = chifra[0];
    key_poly[1] = chifra[1];
    key_poly[2] = chifra[2];
    key_poly[3] = chifra[3];
    key_poly[4] = chifra[4];
    key_poly[5] = chifra[5];
    key_poly[6] = chifra[6];
    key_poly[7] = chifra[7];

    //printfNexys("key poly:");
    //printfNexys("%X %X %X %X\n%X %X %X %X\n",key_poly[0],key_poly[1],key_poly[2],key_poly[3],key_poly[4],key_poly[5],key_poly[6],key_poly[7]);

    for ( int counter = 1; counter < data_length/4; counter += 16)
    {
        chacha20(key_len,numb_rounds,1+(counter/16),key,iv,encrypted+(counter-1),dout,chifra);

        encrypted_temp[counter - 1] = dout[0];
        encrypted_temp[counter + 0] = dout[1];
        encrypted_temp[counter + 1] = dout[2];
        encrypted_temp[counter + 2] = dout[3];
        encrypted_temp[counter + 3] = dout[4];
        encrypted_temp[counter + 4] = dout[5];
        encrypted_temp[counter + 5] = dout[6];
        encrypted_temp[counter + 6] = dout[7];
        encrypted_temp[counter + 7] = dout[8];
        encrypted_temp[counter + 8] = dout[9];
        encrypted_temp[counter + 9] = dout[10];
        encrypted_temp[counter + 10] = dout[11];
        encrypted_temp[counter + 11] = dout[12];
        encrypted_temp[counter + 12] = dout[13];
        encrypted_temp[counter + 13] = dout[14];
        encrypted_temp[counter + 14] = dout[15];

        /*printfNexys("Encrypted bloco dout:"); 
        printfNexys("%X %X  %X  %X", dout[0], dout[1], dout[2], dout[3]);
        printfNexys("%X %X  %X  %X", dout[4], dout[5], dout[6], dout[7]);
        printfNexys("%X %X  %X  %X", dout[8], dout[9], dout[10], dout[11]);
        printfNexys("%X %X  %X  %X", dout[12], dout[13], dout[14], dout[15]);*/

    }

    switch ((4 - (encrypted_length % 4)) % 4)
    {
    case 1:
        encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] & 0xFFFFFF00;
        //encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] >> 8;
        break;
    case 2:
        encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] & 0xFFFF0000;
        //encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] >> 16;
        break;
    case 3:
        encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] & 0xFF000000;
        //encrypted_temp[((encrypted_length) / 4)] = encrypted_temp[((encrypted_length) / 4)] >> 24;
        break;
    
    default:
        break;
    }
    memcpy(data, encrypted_temp, data_length+((((encrypted_length + 3) / 4) * 4) - encrypted_length));

    /*printfNexys("Encrypted:");
    printfNexys("Bloco 1:");  
    printfNexys("%X %X  %X  %X", encrypted[0], encrypted[1], encrypted[2], encrypted[3]);
    printfNexys("%X %X  %X  %X", encrypted[4], encrypted[5], encrypted[6], encrypted[7]);
    printfNexys("%X %X  %X  %X", encrypted[8], encrypted[9], encrypted[10], encrypted[11]);
    printfNexys("%X %X  %X  %X", encrypted[12], encrypted[13], encrypted[14], encrypted[15]);
    printfNexys("Bloco 2:"); 
    printfNexys("%X %X  %X  %X", encrypted[16], encrypted[17], encrypted[18], encrypted[19]);
    printfNexys("%X %X  %X  %X", encrypted[20], encrypted[21], encrypted[22], encrypted[23]);
    printfNexys("%X %X  %X  %X", encrypted[24], encrypted[25], encrypted[26], encrypted[27]);
    printfNexys("%X %X  %X  %X", encrypted[28], encrypted[29], encrypted[30], encrypted[31]);*/
    
    aad_LE = converter_int_para_little_endian(aad_length);
    encrypted_LE = converter_int_para_little_endian(encrypted_length);

    //printfNexys("aad_LE: %X", aad_LE);
    //printfNexys("encrypted_LE: %X", encrypted_LE);

    int AEAD[(aad_length + aad_miss + encrypted_length + encrypted_miss + 16)/4];
    memset(AEAD, 0, sizeof(AEAD));

    for (size_t i = 0; i < aad_length/4; i++)
    {
        AEAD[i]=AAD[i];
    }
    for (size_t i = 0; i < (encrypted_length+3)/4; i++)
    {
        AEAD[i+aad_length/4+aad_miss/4]=encrypted[i];
    }
    AEAD[(aad_length+aad_miss+encrypted_length+encrypted_miss)/4]=aad_LE;
    AEAD[(aad_length+aad_miss+encrypted_length+encrypted_miss)/4+2]=encrypted_LE;

    /*
    printfNexys("AEAD:"); 
    printfNexys("%X %X  %X  %X", AEAD[0], AEAD[1], AEAD[2], AEAD[3]);
    printfNexys("%X %X  %X  %X", AEAD[4], AEAD[5], AEAD[6], AEAD[7]);
    printfNexys("%X %X  %X  %X", AEAD[8], AEAD[9], AEAD[10], AEAD[11]);
    printfNexys("%X %X  %X  %X", AEAD[12], AEAD[13], AEAD[14], AEAD[15]);
    printfNexys("%X %X  %X  %X", AEAD[16], AEAD[17], AEAD[18], AEAD[19]);
    printfNexys("%X %X  %X  %X", AEAD[20], AEAD[21], AEAD[22], AEAD[23]);
    printfNexys("%X %X  %X  %X", AEAD[24], AEAD[25], AEAD[26], AEAD[27]);
    printfNexys("%X %X  %X  %X", AEAD[28], AEAD[29], AEAD[30], AEAD[31]);
    printfNexys("%X %X  %X  %X", AEAD[32], AEAD[33], AEAD[34], AEAD[35]);
    printfNexys("%X %X  %X  %X", AEAD[36], AEAD[37], AEAD[38], AEAD[39]);
    */

    poly1305(block_len,sizeof(AEAD),key_poly,AEAD,mac);

    //printfNexys("Generated tag:"); 
    //printfNexys("%X %X %X %X",mac[0],mac[1],mac[2],mac[3]);

    // Verificar integridade da mensagem
    int res;

    if (memcmp(mac, tag, 4) == 0) {
        res = 1;    // Íntegra
    } else {
        res = 0;    // Adulterado
    }

    return res;
}

int converter_int_para_little_endian(int valor) {
    uint8_t *src = (uint8_t*)&valor;
    int resultado = 0;
    uint8_t *dst = (uint8_t*)&resultado;

    for (int i = 0; i < 4; i++) {
        dst[i] = src[3 - i];  // Inverte os bytes
    }

    return resultado;
}

// Função para converter um número de 64 bits em little-endian
void converter_para_little_endian(uint64_t valor, uint8_t resultado[8]) {
    for (int i = 0; i < 8; i++) {
        resultado[i] = (valor >> (i * 8)) & 0xFF; // Extrai os bytes menos significativos primeiro
    }
}

void int_array_to_char_array_LE(int *int_array, size_t int_array_size, char *char_array) {
    for (size_t i = 0; i < int_array_size; i++) {
        char_array[i * 4 + 0] = (int_array[i] >> 0) & 0xFF;  // 1º byte
        char_array[i * 4 + 1] = (int_array[i] >> 8) & 0xFF;  // 2º byte
        char_array[i * 4 + 2] = (int_array[i] >> 16) & 0xFF; // 3º byte
        char_array[i * 4 + 3] = (int_array[i] >> 24) & 0xFF; // 4º byte
    }
}

void int_array_to_char_array(int *int_array, size_t int_array_size, char *char_array) {
    for (size_t i = 0; i < int_array_size; i++) {
        char_array[i * 4 + 0] = (int_array[i] >> 24) & 0xFF; // 4º byte
        char_array[i * 4 + 1] = (int_array[i] >> 16) & 0xFF; // 3º byte
        char_array[i * 4 + 2] = (int_array[i] >> 8) & 0xFF;  // 2º byte
        char_array[i * 4 + 3] = (int_array[i] >> 0) & 0xFF;  // 1º byte
    }
}

void printHex(char *array, int length) {
    for (int i = 0; i < length; i +=16) {
        printfNexys("%d :  %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X", i,(unsigned char)array[i], (unsigned char)array[i+1], (unsigned char)array[i+2], (unsigned char)array[i+3], (unsigned char)array[i+4], (unsigned char)array[i+5], (unsigned char)array[i+6], (unsigned char)array[i+7], (unsigned char)array[i+8], (unsigned char)array[i+9], (unsigned char)array[i+10], (unsigned char)array[i+11], (unsigned char)array[i+12], (unsigned char)array[i+13], (unsigned char)array[i+14], (unsigned char)array[i+15]); // Cast para evitar problemas com char negativo
    }
    printfNexys("\n");
}

// Assume que o valor_decimal está entre 0 e 999
uint32_t empacotar_ascii_3digitos(int valor_decimal) {
    uint32_t resultado = 0;
    
    // Calcula os dígitos
    int centena = valor_decimal / 100;         // Ex: 568 / 100 = 5
    int dezena  = (valor_decimal / 10) % 10;   // Ex: (568 / 10) % 10 = 6
    int unidade = valor_decimal % 10;          // Ex: 568 % 10 = 8

    // --- Empacotamento ASCII e Deslocamento ---

    // 1. Centena (Dígito mais significativo, vai para o Byte 3)
    // Converte o dígito para ASCII e desloca 24 bits
    resultado |= (uint32_t)(centena + '0') << 24; 

    // 2. Dezena (Byte 2)
    // Converte o dígito para ASCII e desloca 16 bits
    resultado |= (uint32_t)(dezena + '0') << 16; 

    // 3. Unidade (Byte 1)
    // Converte o dígito para ASCII e desloca 8 bits
    resultado |= (uint32_t)(unidade + '0') << 8; 

    // O Byte 0 (posição << 0) será 0, pois o 'resultado' foi inicializado com 0.
    // Assim, garantimos o formato 0xXX XX XX 00.

    return resultado;
}

// Função que converte um valor decimal (0-999) para sua representação BCD empacotada.
// O resultado será um uint16_t (Ex: 568 decimal -> 0x0568 BCD)
uint16_t converter_decimal_para_bcd_999(int valor_decimal) {
    
    // Garantimos o tipo de 16 bits para o resultado
    uint16_t resultado_bcd;

    // 1. Extração dos Dígitos (do mais significativo para o menos significativo)
    
    // Ex: Se valor_decimal = 568
    int centena = valor_decimal / 100;         // 5
    int dezena  = (valor_decimal / 10) % 10;   // 6
    int unidade = valor_decimal % 10;          // 8

    // --- Montagem do BCD em uint16_t ---
    
    // Byte 1 (Bits 15 a 8)
    
    // 1. Centena (Nibble mais significativo, Bits 11-8)
    // Desloca 8 bits para a posição correta
    resultado_bcd = (uint16_t)(centena << 8); 

    // 2. Dezena (Nibble do meio, Bits 7-4)
    // Desloca 4 bits para a posição correta e usa o operador OR
    resultado_bcd |= (uint16_t)(dezena << 4);
    
    // 3. Unidade (Nibble menos significativo, Bits 3-0)
    // A unidade não precisa de deslocamento (<< 0)
    resultado_bcd |= (uint16_t)unidade;
    
    // O BCD resultante está empacotado nos 12 bits inferiores (0x0XXX)

    return resultado_bcd;
}

int main ( void ) 
{ 

    uartInit(); 

    int key[8]; 
    int iv[3]; 
    int AAD[3];
    int tag[4];
    int data[16] = {0};
    int encrypted[16];

    tag[0] = 0x0;
    tag[1] = 0x0;
    tag[2] = 0x0;
    tag[3] = 0x0;

    //printfNexys("Generated MAC:"); 
    //printfNexys("%X %X %X %X",tag[0],tag[1],tag[2],tag[3]);
 
    //printfNexys("ready AEAD_CHACHA20_POLY1305\n"); 
    
    key[0] = 0x80818283; 
    key[1] = 0x84858687;
    key[2] = 0x88898a8b;
    key[3] = 0x8c8d8e8f; 
    key[4] = 0x90919293; 
    key[5] = 0x94959697; 
    key[6] = 0x98999a9b; 
    key[7] = 0x9c9d9e9f;

    //printfNexys("Key:\n%X %X %X %X\n%X %X %X %X",key[0],key[1],key[2],key[3],key[4],key[5],key[6],key[7]);  

    AAD[0] = 0x50515253;
    AAD[1] = 0xc0c1c2c3;
    AAD[2] = 0xc4c5c6c7;

    //printfNexys("AAD:\n%X %X %X\n",AAD[0],AAD[1],AAD[2]); 

    iv[0] = 0x07000000;
    iv[1] = 0x40414243; 
    iv[2] = 0x44454647;

    //printfNexys("N:\n%X %X %X\n",iv[0],iv[1],iv[2]); 

    /*encrypted[0]  = 0xD31A8D34;
    encrypted[1]  = 0x648E60DB;
    encrypted[2]  = 0x7B86AFBC;
    encrypted[3]  = 0x53EF7EC2;
    
    encrypted[4]  = 0xA4ADED51;
    encrypted[5]  = 0x296E08FE;
    encrypted[6]  = 0xA9E2B5A7;
    encrypted[7]  = 0x36EE62D6;
    
    encrypted[8]  = 0x3DBEA45E;
    encrypted[9]  = 0x8CA96712;
    encrypted[10] = 0x82FAFB69;
    encrypted[11] = 0xDA92728B;
    
    encrypted[12] = 0x1A71DE0A;
    encrypted[13] = 0x9E060B29;
    encrypted[14] = 0x05D6A5B6;
    encrypted[15] = 0x7ECD3B36;
    
    encrypted[16] = 0x92DDBD7F;
    encrypted[17] = 0x2D778B8C;
    encrypted[18] = 0x9803AEE3;
    encrypted[19] = 0x28091B58;
    
    encrypted[20] = 0xFAB324E4;
    encrypted[21] = 0xFAD67594;
    encrypted[22] = 0x5585808B;
    encrypted[23] = 0x4831D7BC;
    
    encrypted[24] = 0x3FF4DEF0;
    encrypted[25] = 0x8E4B7A9D;
    encrypted[26] = 0xE576D265;
    encrypted[27] = 0x86CEC64B;
    
    encrypted[28] = 0x61160000;
    encrypted[29] = 0x00000000;
    encrypted[30] = 0x00000000;
    encrypted[31] = 0x00000000;*/

    data[0]  = 0x4F207661;   // O   v a
    data[1]  = 0x6C6F7220;   // l o r
    data[2]  = 0x64652074;   // d e   t
    data[3]  = 0x656E7361;   // e n s a
    data[4]  = 0x6F206D65;   // o   m e
    data[5]  = 0x6469646F;   // d i d o
    data[6]  = 0x2070656C;   //   p e l
    data[7]  = 0x6F205841;   // o   X A
    data[8]  = 0x44432066;   // D C   f
    data[9]  = 0x6F693A20;   // o i :
    data[10] = 0x00000000;   // X X X
    data[11] = 0x6D560000;   // m V 0 0
    data[12] = 0x00000000;
    data[13] = 0x00000000;
    data[14] = 0x00000000;
    data[15] = 0x00000000;

    int comp_msg = 46;
    /*data[16] = 0x00000000;
    data[17] = 0x00000000;
    data[18] = 0x00000000;
    data[19] = 0x00000000;
    data[20] = 0x00000000;
    data[21] = 0x00000000;
    data[22] = 0x00000000;
    data[23] = 0x00000000;
    data[24] = 0x00000000;
    data[25] = 0x00000000;
    data[26] = 0x00000000;
    data[27] = 0x00000000;
    data[28] = 0x00000000;
    data[29] = 0x00000000;
    data[30] = 0x00000000;
    data[31] = 0x00000000;*/

    while (1)
{
    
    int adr_adc, crtl_adc, adrc_adc, data_adc, adrmem_adc, test_adc;

    //Test wishbone reading on module
    //test_adc = READ_WB(TESTE_XADC);
    //printfNexys("Test value: %d ", test_adc);
    //Execute a reading on XADC Event-Driven on ADR_XADC 13
    adr_adc = 0x13;
    crtl_adc = 0x01;

    WRITE_WB(ADR_XADC,adr_adc);
    WRITE_WB(CRTL_XADC,crtl_adc);

    //adrc_adc = READ_WB(ADR_XADC);

    //printfNexys("Value reading address: %X",adrc_adc);

    //adrc_adc = READ_WB(ADR_XADC);

    WRITE_WB(RW_XADC,0x1);


    int wait_adc=1; 
    int estado_adc=0x00; 

    while (wait_adc==1) { 
        estado_adc=READ_WB(STATUS_XADC); 
        if (estado_adc!=0x00){ 
            wait_adc=0; 
        } 
    } 

    data_adc =((READ_WB(DATA_XADC) >> 4)*1000)/4096;

    //printfNexys("Tensão medida pelo XADC: %d mV",data_adc); 

    data[10] = empacotar_ascii_3digitos(data_adc);
    data[10] = (data[10] & 0xFFFFFF00) | 0x20;
    //data[10] = (0x20 << 24) | (data[10] >> 8);

    WRITE_WB(SegEn_ADDR, 0x00);
    WRITE_WB(SegDig_ADDR, converter_decimal_para_bcd_999(data_adc));

    /*
    printfNexys("Data:"); 
    printfNexys("Bloco 1:"); 
    printfNexys("%X %X  %X  %X", data[0], data[1], data[2], data[3]);
    printfNexys("%X %X  %X  %X", data[4], data[5], data[6], data[7]);
    printfNexys("%X %X  %X  %X", data[8], data[9], data[10], data[11]);
    printfNexys("%X %X  %X  %X", data[12], data[13], data[14], data[15]);
    printfNexys("Bloco 2:"); 
    printfNexys("%X %X  %X  %X", data[16], data[17], data[18], data[19]);
    printfNexys("%X %X  %X  %X", data[20], data[21], data[22], data[23]);
    printfNexys("%X %X  %X  %X", data[24], data[25], data[26], data[27]);
    printfNexys("%X %X  %X  %X", data[28], data[29], data[30], data[31]);
    */
    //int res;

    //res = AEAD_chacha20_poly1305_receive(key, iv, AAD, sizeof(AAD), encrypted, 114, data , tag);

    AEAD_chacha20_poly1305_send(key, iv, AAD, sizeof(AAD), data, comp_msg, encrypted , tag);

    /*
    printfNexys("Encrypted:"); 
    printfNexys("Bloco 1:"); 
    printfNexys("%X %X  %X  %X", encrypted[0], encrypted[1], encrypted[2], encrypted[3]);
    printfNexys("%X %X  %X  %X", encrypted[4], encrypted[5], encrypted[6], encrypted[7]);
    printfNexys("%X %X  %X  %X", encrypted[8], encrypted[9], encrypted[10], encrypted[11]);
    printfNexys("%X %X  %X  %X", encrypted[12], encrypted[13], encrypted[14], encrypted[15]);
    printfNexys("Bloco 2:"); 
    printfNexys("%X %X  %X  %X", encrypted[16], encrypted[17], encrypted[18], encrypted[19]);
    printfNexys("%X %X  %X  %X", encrypted[20], encrypted[21], encrypted[22], encrypted[23]);
    printfNexys("%X %X  %X  %X", encrypted[24], encrypted[25], encrypted[26], encrypted[27]);
    printfNexys("%X %X  %X  %X", encrypted[28], encrypted[29], encrypted[30], encrypted[31]);

    printfNexys("Data:"); 
    printfNexys("Bloco 1:"); 
    printfNexys("%X %X  %X  %X", data[0], data[1], data[2], data[3]);
    printfNexys("%X %X  %X  %X", data[4], data[5], data[6], data[7]);
    printfNexys("%X %X  %X  %X", data[8], data[9], data[10], data[11]);
    printfNexys("%X %X  %X  %X", data[12], data[13], data[14], data[15]);
    printfNexys("Bloco 2:"); 
    printfNexys("%X %X  %X  %X", data[16], data[17], data[18], data[19]);
    printfNexys("%X %X  %X  %X", data[20], data[21], data[22], data[23]);
    printfNexys("%X %X  %X  %X", data[24], data[25], data[26], data[27]);
    printfNexys("%X %X  %X  %X", data[28], data[29], data[30], data[31]);
    */

    /*
    if (res){
        printfNexys("\nMensagem Integra");
    } else{
        printfNexys("\nMensagem Adulterado");
    }
    printfNexys("\n");
    */

    //uart_puts("UART pronta!");

    unsigned char str[comp_msg+16];
    //int buffer[(sizeof(encrypted)/4)+4];
    unsigned char buffer_encrypted[64];
    unsigned char buffer_tag[16];

    //memcpy(buffer, encrypted, comp_msg);
    //memcpy(buffer + (comp_msg/4), tag, 16);

    //int_array_to_char_array(buffer,sizeof(buffer), str);

    int_array_to_char_array(encrypted, (sizeof(encrypted)/4), buffer_encrypted);
    int_array_to_char_array(tag,4 , buffer_tag);

    memcpy(str, buffer_encrypted, comp_msg);
    memcpy(str + comp_msg, buffer_tag, 16);




/*
printfNexys(
    "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
    
    str[0],  str[1],  str[2],  str[3],  str[4],  str[5],  str[6],  str[7],
    str[8],  str[9],  str[10], str[11], str[12], str[13], str[14], str[15],
    str[16], str[17], str[18], str[19], str[20], str[21], str[22], str[23],
    str[24], str[25], str[26], str[27], str[28], str[29], str[30], str[31],
    str[32], str[33], str[34], str[35], str[36], str[37], str[38], str[39],
    str[40], str[41], str[42], str[43], str[44], str[45], str[46], str[47],
    str[48], str[49], str[50], str[51], str[52], str[53], str[54], str[55],
    str[56], str[57], str[58], str[59], str[60], str[61], str[62], str[63],
    str[64], str[65], str[66], str[67], str[68], str[69], str[70], str[71],
    str[72], str[73], str[74], str[75], str[76], str[77], str[78], str[79],
    str[80], str[81], str[82], str[83], str[84], str[85], str[86], str[87],
    str[88], str[89], str[90], str[91], str[92], str[93], str[94], str[95],
    str[96], str[97], str[98], str[99], str[100], str[101], str[102], str[103],
    str[104], str[105], str[106], str[107], str[108], str[109], str[110], str[111],
    str[112], str[113], str[114], str[115], str[116], str[117], str[118], str[119],
    str[120], str[121], str[122], str[123], str[124], str[125], str[126], str[127],
    str[128], str[129], str[130], str[131], str[132], str[133], str[134], str[135],
    str[136], str[137], str[138], str[139], str[140], str[141], str[142], str[143]
);    */

/*
for (int i = 0; i < 144; i++) {
    printfNexys("%c", str[i]);
}
*/

/*
printfNexys("%s\n",str);
printfNexys("%s\n",buffer_encrypted);
printfNexys("%s\n",buffer_tag);


printfNexys("Final: %s\n",str);
printHex(str,62);

printfNexys("MAC: %s",buffer_tag);
printHex(buffer_tag,16);

printfNexys("encrypted: %s",buffer_encrypted);
printHex(buffer_encrypted,46);*/



    printfNexys(
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X",
        /*%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X",*/
        
        (unsigned char)str[0],  (unsigned char)str[1],  (unsigned char)str[2],  (unsigned char)str[3],
        (unsigned char)str[4],  (unsigned char)str[5],  (unsigned char)str[6],  (unsigned char)str[7],
        (unsigned char)str[8],  (unsigned char)str[9],  (unsigned char)str[10], (unsigned char)str[11],
        (unsigned char)str[12], (unsigned char)str[13], (unsigned char)str[14], (unsigned char)str[15],
        (unsigned char)str[16], (unsigned char)str[17], (unsigned char)str[18], (unsigned char)str[19],
        (unsigned char)str[20], (unsigned char)str[21], (unsigned char)str[22], (unsigned char)str[23],
        (unsigned char)str[24], (unsigned char)str[25], (unsigned char)str[26], (unsigned char)str[27],
        (unsigned char)str[28], (unsigned char)str[29], (unsigned char)str[30], (unsigned char)str[31],
        (unsigned char)str[32], (unsigned char)str[33], (unsigned char)str[34], (unsigned char)str[35],
        (unsigned char)str[36], (unsigned char)str[37], (unsigned char)str[38], (unsigned char)str[39],
        (unsigned char)str[40], (unsigned char)str[41], (unsigned char)str[42], (unsigned char)str[43],
        (unsigned char)str[44], (unsigned char)str[45], (unsigned char)str[46], (unsigned char)str[47],
        (unsigned char)str[48], (unsigned char)str[49], (unsigned char)str[50], (unsigned char)str[51],
        (unsigned char)str[52], (unsigned char)str[53], (unsigned char)str[54], (unsigned char)str[55],
        (unsigned char)str[56], (unsigned char)str[57], (unsigned char)str[58], (unsigned char)str[59],
        (unsigned char)str[60], (unsigned char)str[61]/*, (unsigned char)str[62], (unsigned char)str[63],
        (unsigned char)str[64], (unsigned char)str[65], (unsigned char)str[66], (unsigned char)str[67],
        (unsigned char)str[68], (unsigned char)str[69], (unsigned char)str[70], (unsigned char)str[71],
        (unsigned char)str[72], (unsigned char)str[73], (unsigned char)str[74], (unsigned char)str[75],
        (unsigned char)str[76], (unsigned char)str[77], (unsigned char)str[78], (unsigned char)str[79],
        (unsigned char)str[80], (unsigned char)str[81], (unsigned char)str[82], (unsigned char)str[83],
        (unsigned char)str[84], (unsigned char)str[85], (unsigned char)str[86], (unsigned char)str[87],
        (unsigned char)str[88], (unsigned char)str[89], (unsigned char)str[90], (unsigned char)str[91],
        (unsigned char)str[92], (unsigned char)str[93], (unsigned char)str[94], (unsigned char)str[95],
        (unsigned char)str[96], (unsigned char)str[97], (unsigned char)str[98], (unsigned char)str[99],
        (unsigned char)str[100], (unsigned char)str[101], (unsigned char)str[102], (unsigned char)str[103],
        (unsigned char)str[104], (unsigned char)str[105], (unsigned char)str[106], (unsigned char)str[107],
        (unsigned char)str[108], (unsigned char)str[109], (unsigned char)str[110], (unsigned char)str[111],
        (unsigned char)str[112], (unsigned char)str[113], (unsigned char)str[114], (unsigned char)str[115],
        (unsigned char)str[116], (unsigned char)str[117], (unsigned char)str[118], (unsigned char)str[119],
        (unsigned char)str[120], (unsigned char)str[121], (unsigned char)str[122], (unsigned char)str[123],
        (unsigned char)str[124], (unsigned char)str[125], (unsigned char)str[126], (unsigned char)str[127],
        (unsigned char)str[128], (unsigned char)str[129], (unsigned char)str[130], (unsigned char)str[131],
        (unsigned char)str[132], (unsigned char)str[133], (unsigned char)str[134], (unsigned char)str[135],
        (unsigned char)str[136], (unsigned char)str[137], (unsigned char)str[138], (unsigned char)str[139],
        (unsigned char)str[140], (unsigned char)str[141], (unsigned char)str[142], (unsigned char)str[143]*/
    );

    int i;

    for(i=0;i<DELAY;i++){
        i=i+1;
    }
    
}
    return(0); 
}
