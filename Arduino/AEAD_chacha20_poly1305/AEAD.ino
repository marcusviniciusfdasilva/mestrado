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
    //chacha_encrypt_bytes(&ctx, zero_input, key_poly, sizeof(zero_input));
    chacha_encrypt_bytes(&ctx, (const unsigned char*)zero_input, key_poly, sizeof(zero_input));


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

    return;
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
    //chacha_encrypt_bytes(&ctx, zero_input, key_poly, sizeof(zero_input));
    chacha_encrypt_bytes(&ctx, (const unsigned char*)zero_input, key_poly, sizeof(zero_input));

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

    return res;
}

void setup() {
    Serial.begin(9600);  // Inicia a comunicação serial do PC a 9600 bps
    Serial1.begin(115200); // Para comunicação HUart externa

    unsigned char key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };

    unsigned char iv[12] = {
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };

    unsigned char AAD[12] = {
        0x50, 0x51, 0x52, 0x53,
        0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };

    unsigned char encrypted[] = {
        0xD3, 0x1A, 0x8D, 0x34, 
        0x64, 0x8E, 0x60, 0xDB, 
        0x7B, 0x86, 0xAF, 0xBC, 
        0x53, 0xEF, 0x7E, 0xC2, 
        0xA4, 0xAD, 0xED, 0x51, 
        0x29, 0x6E, 0x08, 0xFE, 
        0xA9, 0xE2, 0xB5, 0xA7, 
        0x36, 0xEE, 0x62, 0xD6, 
        0x3D, 0xBE, 0xA4, 0x5E, 
        0x8C, 0xA9, 0x67, 0x12, 
        0x82, 0xFA, 0xFB, 0x69, 
        0xDA, 0x92, 0x72, 0x8B, 
        0x1A, 0x71, 0xDE, 0x0A, 
        0x9E, 0x06, 0x0B, 0x29, 
        0x05, 0xD6, 0xA5, 0xB6, 
        0x7E, 0xCD, 0x3B, 0x36, 
        0x92, 0xDD, 0xBD, 0x7F, 
        0x2D, 0x77, 0x8B, 0x8C, 
        0x98, 0x03, 0xAE, 0xE3, 
        0x28, 0x09, 0x1B, 0x58, 
        0xFA, 0xB3, 0x24, 0xE4, 
        0xFA, 0xD6, 0x75, 0x94, 
        0x55, 0x85, 0x80, 0x8B, 
        0x48, 0x31, 0xD7, 0xBC, 
        0x3F, 0xF4, 0xDE, 0xF0, 
        0x8E, 0x4B, 0x7A, 0x9D, 
        0xE5, 0x76, 0xD2, 0x65, 
        0x86, 0xCE, 0xC6, 0x4B, 
        0x61, 0x16
    };   

    unsigned char data[sizeof(encrypted)];

    unsigned char tag[32] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };

    while (1) { 
        int res = AEAD_chacha20_poly1305_receive((const unsigned char*)key, (const unsigned char*)iv, (const unsigned char*)AAD, sizeof(AAD), (const unsigned char*)encrypted, sizeof(encrypted), data, (const unsigned char*)tag);

        Serial.println("Tag recebido:");
        for (int i = 0; i < POLY1305_TAGLEN; i++) {
            Serial.print(tag[i], HEX);
            Serial.print(" ");
        }
        Serial.println(" ");

        Serial.println("encrypted recebido:");
        for (int i = 0; i < sizeof(encrypted); i++) {
            Serial.print(encrypted[i], HEX);
            Serial.print(" ");
            if ((i + 1) % 4 == 0) {
                Serial.print("  ");
            }
            if ((i + 1) % 16 == 0) {
                Serial.println();
            }
        }

        Serial.println(" ");

        Serial.println("Data:");
        for (int i = 0; i < sizeof(data); i++) {
            Serial.print(data[i], HEX);
            Serial.print(" ");
            if ((i + 1) % 4 == 0) {
                Serial.print("  ");
            }
            if ((i + 1) % 16 == 0) {
                Serial.println();
            }
        }

        Serial.println(" ");

        char str[115];                  
        memcpy(str, data, 114);         
        str[114] = '\0';                
        Serial.println(str);            

        memcpy(str, encrypted, 114);    
        str[114] = '\0';                
        Serial.println(str);            

        if (res){
            Serial.println("Mensagem Integra");
        } else {
            Serial.println("Mensagem Adulterado");
        }

        Serial.println();

        delay(5000);
    }
}

void loop() {
  // Função vazia para o Arduino, já que estamos realizando tudo na função setup()
}



