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

int main ( void ) 
{ 

    uartInit(); 

    int key[8]; 
    int iv[3]; 
    int AAD[3];
    int tag[4];
    int data[32] = {0};
    int data2[32] = {0};
    int encrypted[32];

    /*tag[0] = 0x1AE10B59;
    tag[1] = 0x4F09E26A;
    tag[2] = 0x7E902ECB;
    tag[3] = 0xD0600691;

    printfNexys("MAC:"); 
    printfNexys("%X %X %X %X\n",tag[0],tag[1],tag[2],tag[3]);*/
    
    key[0] = 0x80818283; 
    key[1] = 0x84858687;
    key[2] = 0x88898a8b;
    key[3] = 0x8c8d8e8f; 
    key[4] = 0x90919293; 
    key[5] = 0x94959697; 
    key[6] = 0x98999a9b; 
    key[7] = 0x9c9d9e9f;

    printfNexys("Key:\n%X %X %X %X\n%X %X %X %X\n",key[0],key[1],key[2],key[3],key[4],key[5],key[6],key[7]);  

    AAD[0] = 0x50515253;
    AAD[1] = 0xc0c1c2c3;
    AAD[2] = 0xc4c5c6c7;

    printfNexys("AAD:\n%X %X %X\n",AAD[0],AAD[1],AAD[2]); 

    iv[0] = 0x07000000;
    iv[1] = 0x40414243; 
    iv[2] = 0x44454647;

    printfNexys("iv:\n%X %X %X\n",iv[0],iv[1],iv[2]); 

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


    data[0] = 0x4c616469;
    data[1] = 0x65732061;
    data[2] = 0x6e642047;
    data[3] = 0x656e746c;
    data[4] = 0x656d656e;
    data[5] = 0x206f6620;
    data[6] = 0x74686520;
    data[7] = 0x636c6173;
    data[8] = 0x73206f66;
    data[9] = 0x20273939;
    data[10] = 0x3a204966; 
    data[11] = 0x20492063;
    data[12] = 0x6f756c64;
    data[13] = 0x206f6666;
    data[14] = 0x65722079;
    data[15] = 0x6f75206f;

    data[16] = 0x6e6c7920;
    data[17] = 0x6f6e6520;
    data[18] = 0x74697020;
    data[19] = 0x666f7220;
    data[20] = 0x74686520;
    data[21] = 0x66757475;
    data[22] = 0x72652c20;
    data[23] = 0x73756e73;
    data[24] = 0x63726565;
    data[25] = 0x6e20776f;
    data[26] = 0x756c6420;
    data[27] = 0x62652069;
    data[28] = 0x742e0000;
    data[29] = 0x00000000;
    data[30] = 0x00000000;
    data[31] = 0x00000000;
    
    
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
    printfNexys("\n");

    //printfNexys("AEAD_CHACHA20_POLY1305\n"); 

    AEAD_chacha20_poly1305_send(key, iv, AAD, sizeof(AAD), data, 114, encrypted , tag);

    printfNexys("Tag generated:"); 
    printfNexys("%X %X %X %X\n",tag[0],tag[1],tag[2],tag[3]);

    //encrypted[0] = 0x4c1a8d34;

    printfNexys("Encrypted generated:"); 
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
    printfNexys("\n");

    int res;

    res = AEAD_chacha20_poly1305_receive(key, iv, AAD, sizeof(AAD), encrypted, 114, data2 , tag);

    printfNexys("Data decrypted:"); 
    printfNexys("Bloco 1:"); 
    printfNexys("%X %X  %X  %X", data2[0], data2[1], data2[2], data2[3]);
    printfNexys("%X %X  %X  %X", data2[4], data2[5], data2[6], data2[7]);
    printfNexys("%X %X  %X  %X", data2[8], data2[9], data2[10], data2[11]);
    printfNexys("%X %X  %X  %X", data2[12], data2[13], data2[14], data2[15]);
    printfNexys("Bloco 2:"); 
    printfNexys("%X %X  %X  %X", data2[16], data2[17], data2[18], data2[19]);
    printfNexys("%X %X  %X  %X", data2[20], data2[21], data2[22], data2[23]);
    printfNexys("%X %X  %X  %X", data2[24], data2[25], data2[26], data2[27]);
    printfNexys("%X %X  %X  %X", data2[28], data2[29], data2[30], data2[31]);
    printfNexys("\n");
    

    //AEAD_chacha20_poly1305_send(key, iv, AAD, sizeof(AAD), data, 114, encrypted , tag);

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
    printfNexys("%X %X  %X  %X", encrypted[28], encrypted[29], encrypted[30], encrypted[31]);

    printfNexys("\n"); 

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
    printfNexys("%X %X  %X  %X", data[28], data[29], data[30], data[31]);*/
    
    if (res){
        printfNexys("\nMensagem Integra");
    } else{
        printfNexys("\nMensagem Adulterada");
    }
    printfNexys("\n");  
    
    unsigned char buffer_data[150];
    unsigned char buffer_encrypted[150];

    int_array_to_char_array(data2, (sizeof(data2)/4), buffer_data);
    int_array_to_char_array(encrypted, (sizeof(encrypted)/4), buffer_encrypted);

    buffer_data[114]='\0';
    buffer_encrypted[114]='\0';
    
    printfNexys("Mensagem:");
    printfNexys("%s",buffer_data);
    printfNexys("\n");
    printfNexys("Mensagem Encrypted:");
    printfNexys("%s",buffer_encrypted);

    return(0); 
}
