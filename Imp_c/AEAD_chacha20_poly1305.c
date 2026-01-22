#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "chacha.h"
#include "chacha.c"

#include "poly1305.h"
#include "poly1305.c"

int verificarMultiplo(int numero) {
    if (numero % 16 == 0) {
        //printf("%d é múltiplo de 16.\n", numero);
        return 0; // Não falta nenhum valor.
    } else {
        int resto = numero % 16;
        int faltam = 16 - resto;
        //printf("%d não é múltiplo de 16. Faltam %d valores para o próximo múltiplo de 16.\n", numero, faltam);
        return faltam; // Retorna o valor que falta.
    }
}

// Função para converter um número de 64 bits em little-endian
void converter_para_little_endian(uint64_t valor, uint8_t resultado[8]) {
    for (int i = 0; i < 8; i++) {
        resultado[i] = (valor >> (i * 8)) & 0xFF; // Extrai os bytes menos significativos primeiro
    }
}

void AEAD_chacha20_poly1305_send(const unsigned char *key, const unsigned char *iv, const unsigned char *AAD, size_t aad_length, const unsigned char *data, size_t data_length, unsigned char *encrypted, unsigned char *tag) {

    struct chacha_ctx ctx;

    size_t encrypted_length = data_length;

    uint8_t aad_LE[8];
    uint8_t encrypted_LE[8];
    
    //size_t aad_length = sizeof(AAD);
    //size_t encrypted_length = sizeof(encrypted);

    unsigned char counter[4] = { 0x01, 0x00, 0x00, 0x00 };

    // Descriptografar mensagem
    chacha_keysetup(&ctx, key, 256);
    chacha_ivsetup(&ctx, iv, counter);
    chacha_encrypt_bytes(&ctx, data, encrypted, data_length);

    char zero_input[32] = {0};
    unsigned char key_poly[32];
    memset(counter, 0x00, 4);

    // Gerar key do poly1305
    chacha_ivsetup(&ctx, iv, counter);
    chacha_encrypt_bytes(&ctx, zero_input, key_poly, sizeof(zero_input));

    int aad_miss = verificarMultiplo(aad_length);
    int encrypted_miss = verificarMultiplo(data_length);

    converter_para_little_endian(aad_length, aad_LE);
    converter_para_little_endian(encrypted_length, encrypted_LE);

    unsigned char AEAD[aad_length + aad_miss + encrypted_length + encrypted_miss + 16];

    // AEAD Construction for poly1305
    memcpy(AEAD, AAD, aad_length);                                                                  // Copia o conteúdo de AAD para AEAD
    memset(AEAD + aad_length, 0x00, aad_miss);                                                      // Zerar até multiplo de 16
    memcpy(AEAD + aad_length + aad_miss, encrypted, encrypted_length);                              // Copia encrypted após AAD
    memset(AEAD + aad_length + aad_miss + encrypted_length, 0x00, encrypted_miss);                  // Zerar até multiplo de 16
    memcpy(AEAD + aad_length + aad_miss + encrypted_length + encrypted_miss, aad_LE, 8);            // aad_length [little_endian]
    memcpy(AEAD + aad_length + aad_miss + encrypted_length + encrypted_miss + 8, encrypted_LE, 8);  // encrypted_length [little_endian]

    // Mensagem a ser autenticada
    const unsigned char *message = (const unsigned char *)AEAD;
    size_t message_length = strlen((const char *)message);    

    // Calcular o MAC usando Poly1305
    poly1305_auth(tag, AEAD, sizeof(AEAD), key_poly);

/*
    printf("Key Poly1305:\n");
    for (int i = 0; i < sizeof(key_poly); i++) {
        printf("%02X ", key_poly[i]);
    }
    printf("\n");
    printf("AEAD:\n");
    for (int i = 0; i < sizeof(AEAD); i++) {
        printf("%02X ", AEAD[i]);
    }
    printf("\n");
    printf("Tamanho do AEAD: %d\n", (int)sizeof(AEAD));
    printf("MAC gerado:\n");
    for (int i = 0; i < POLY1305_TAGLEN; i++) {
        printf("%02x ", mac[i]);
    }
    printf("\n");*/

    return 0;
}

int AEAD_chacha20_poly1305_receive(const unsigned char *key, const unsigned char *iv, const unsigned char *AAD, size_t aad_length, const unsigned char *encrypted, size_t encrypted_length, unsigned char *data, const unsigned char *tag) {

    struct chacha_ctx ctx;

    uint8_t aad_LE[8];
    uint8_t encrypted_LE[8];
    
    //size_t aad_length = sizeof(AAD);
    //size_t encrypted_length = sizeof(encrypted);

    unsigned char counter[4] = { 0x01, 0x00, 0x00, 0x00 };

    // Descriptografar mensagem
    chacha_keysetup(&ctx, key, 256);
    chacha_ivsetup(&ctx, iv, counter);
    chacha_encrypt_bytes(&ctx, encrypted, data, encrypted_length);

    char zero_input[32] = {0};
    unsigned char key_poly[32];
    memset(counter, 0x00, 4);

    // Gerar key do poly1305
    chacha_ivsetup(&ctx, iv, counter);
    chacha_encrypt_bytes(&ctx, zero_input, key_poly, sizeof(zero_input));

    int aad_miss = verificarMultiplo(aad_length);
    int encrypted_miss = verificarMultiplo(encrypted_length);

    converter_para_little_endian(aad_length, aad_LE);
    converter_para_little_endian(encrypted_length, encrypted_LE);

    unsigned char AEAD[aad_length + aad_miss + encrypted_length + encrypted_miss + 16];

    // AEAD Construction for poly1305
    memcpy(AEAD, AAD, aad_length);                                                                  // Copia o conteúdo de AAD para AEAD
    memset(AEAD + aad_length, 0x00, aad_miss);                                                      // Zerar até multiplo de 16
    memcpy(AEAD + aad_length + aad_miss, encrypted, encrypted_length);                              // Copia encrypted após AAD
    memset(AEAD + aad_length + aad_miss + encrypted_length, 0x00, encrypted_miss);                  // Zerar até multiplo de 16
    memcpy(AEAD + aad_length + aad_miss + encrypted_length + encrypted_miss, aad_LE, 8);            // aad_length [little_endian]
    memcpy(AEAD + aad_length + aad_miss + encrypted_length + encrypted_miss + 8, encrypted_LE, 8);  // encrypted_length [little_endian]

    // Mensagem a ser autenticada
    const unsigned char *message = (const unsigned char *)AEAD;
    size_t message_length = strlen((const char *)message);    

    // Buffer para armazenar o MAC (tag de autenticação)
    unsigned char mac[POLY1305_TAGLEN];

    // Calcular o MAC usando Poly1305
    poly1305_auth(mac, AEAD, sizeof(AEAD), key_poly);

    // Verificar integridade da mensagem
    int res;

    if (memcmp(mac, tag, 16) == 0) {
        res = 1;    // Íntegra
    } else {
        res = 0;    // Adulterado
    }

/*
    printf("Key Poly1305:\n");
    for (int i = 0; i < sizeof(key_poly); i++) {
        printf("%02X ", key_poly[i]);
    }
    printf("\n");
    printf("AEAD:\n");
    for (int i = 0; i < sizeof(AEAD); i++) {
        printf("%02X ", AEAD[i]);
    }
    printf("\n");
    printf("Tamanho do AEAD: %d\n", (int)sizeof(AEAD));
    printf("MAC gerado:\n");
    for (int i = 0; i < POLY1305_TAGLEN; i++) {
        printf("%02x ", mac[i]);
    }
    printf("\n");*/

    return res;
}

int main() {

    int res;
    unsigned char key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };

    printf("key:\n");
        for (int i = 0; i < sizeof(key); i++) {
            printf("%02x", key[i]);
        }
    printf("\n");

    unsigned char iv[12] = {
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };

    printf("iv:\n");
        for (int i = 0; i < sizeof(iv); i++) {
            printf("%02x", iv[i]);
        }
    printf("\n");

    unsigned char AAD[12] = {
        0x50, 0x51, 0x52, 0x53,
        0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };
    
    printf("AAD:\n");
        for (int i = 0; i < sizeof(AAD); i++) {
            printf("%02x", AAD[i]);
        }
    printf("\n"); 

    unsigned char data[] = {
        0x4C, 0x61, 0x64, 0x69,
        0x65, 0x73, 0x20, 0x61, 
        0x6E, 0x64, 0x20, 0x47, 
        0x65, 0x6E, 0x74, 0x6C, 
        
        0x65, 0x6D, 0x65, 0x6E, 
        0x20, 0x6F, 0x66, 0x20, 
        0x74, 0x68, 0x65, 0x20, 
        0x63, 0x6C, 0x61, 0x73, 
        
        0x73, 0x20, 0x6F, 0x66, 
        0x20, 0x27, 0x39, 0x39, 
        0x3A, 0x20, 0x49, 0x66, 
        0x20, 0x49, 0x20, 0x63, 
        
        0x6F, 0x75, 0x6C, 0x64, 
        0x20, 0x6F, 0x66, 0x66, 
        0x65, 0x72, 0x20, 0x79, 
        0x6F, 0x75, 0x20, 0x6F, 
        
        0x6E, 0x6C, 0x79, 0x20, 
        0x6F, 0x6E, 0x65, 0x20, 
        0x74, 0x69, 0x70, 0x20, 
        0x66, 0x6F, 0x72, 0x20,
        
        0x74, 0x68, 0x65, 0x20, 
        0x66, 0x75, 0x74, 0x75, 
        0x72, 0x65, 0x2C, 0x20, 
        0x73, 0x75, 0x6E, 0x73, 
        
        0x63, 0x72, 0x65, 0x65, 
        0x6E, 0x20, 0x77, 0x6F, 
        0x75, 0x6C, 0x64, 0x20, 
        0x62, 0x65, 0x20, 0x69,
        
        0x74, 0x2E 
    };

    printf("Data:\n");
        for (int i = 0; i < sizeof(data); i++) {
            printf("%02x", data[i]);
        }
    printf("\n");

    unsigned char encrypted[sizeof(data)];
    unsigned char data2[sizeof(data)];
    unsigned char tag[16] = {0};

    AEAD_chacha20_poly1305_send(key, iv, AAD, sizeof(AAD), data, sizeof(data), encrypted, tag);

    printf("Tag generated:\n");
    for (int i = 0; i < sizeof(tag); i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");

    //encrypted[0]=0x4C;

    printf("Encrypted generated:\n");
    for (int i = 0; i < sizeof(encrypted); i++) {
        printf("%02X", encrypted[i]);
    }
    printf("\n");
    
    res = AEAD_chacha20_poly1305_receive(key, iv, AAD, sizeof(AAD), encrypted, sizeof(encrypted), data2, tag);

    printf("Data decrypted:\n");
    for (int i = 0; i < sizeof(data); i++) {
        printf("%02X", data2[i]);
    }

    if (res){
        printf("\nMensagem Integra");
    } else{
        printf("\nMensagem Adulterada");
    }
    printf("\n");

    char str[115];                  
    
    printf("Mensagem:\n");
    memcpy(str, data2, 114);       
    str[114] = '\0';                
    printf("%s\n", str);            
    
    printf("Mensagem Encrypted:\n");
    memcpy(str, encrypted, 114);    
    str[114] = '\0';                
    printf("%s\n", str);            
    
}