#include <windows.h>
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

HANDLE init_serial(const char *port) {
    HANDLE hSerial = CreateFileA(
        port,                       // Nome da porta (ex: "COM3")
        GENERIC_READ | GENERIC_WRITE,
        0,                          // Sem compartilhamento
        NULL,                       // Segurança padrão
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hSerial == INVALID_HANDLE_VALUE) {
        printf("Erro ao abrir porta %s\n", port);
        return INVALID_HANDLE_VALUE;
    }

    // Configura parâmetros da porta
    DCB dcbSerialParams = {0};
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);

    if (!GetCommState(hSerial, &dcbSerialParams)) {
        printf("Erro ao obter estado da porta\n");
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }

    dcbSerialParams.BaudRate = CBR_115200;  // Baudrate
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity   = NOPARITY;

    if (!SetCommState(hSerial, &dcbSerialParams)) {
        printf("Erro ao configurar porta\n");
        CloseHandle(hSerial);
        return INVALID_HANDLE_VALUE;
    }

    // Timeout
    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 50;
    timeouts.ReadTotalTimeoutConstant = 0;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 100;
    timeouts.WriteTotalTimeoutMultiplier = 10;

    SetCommTimeouts(hSerial, &timeouts);

    return hSerial;
}

// Converte um caractere hexadecimal em valor numérico (0-15)
int hexchar_to_int(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    return -1; // caractere inválido
}

// Converte string ASCII "0xXX" ou "0xXX " para bytes binários
// hex_str: string recebida do SoC
// out: buffer de saída com 144 bytes
// length: número de bytes a gerar (144)
int hexstring_to_bytes(const char *hex_str, unsigned char *out, int length) {
    int idx = 0;  // índice no buffer de saída
    int hi = -1, lo = -1;

    for (const char *p = hex_str; *p != '\0'; p++) {
        // ignora espaços e quebras de linha
        if (*p == ' ' || *p == '\n' || *p == '\r') continue;

        // ignora "0x" ou "0X"
        if (*p == '0' && (*(p+1) == 'x' || *(p+1) == 'X')) {
            p++; // pula o 'x' também
            continue;
        }

        int val = hexchar_to_int(*p);
        if (val < 0) return -1; // caractere inválido

        if (hi < 0) {
            hi = val;
        } else {
            lo = val;
            if (idx >= length) return -1; // overflow
            out[idx++] = (hi << 4) | lo;
            hi = lo = -1;
        }
    }

    return (idx == length) ? 0 : -1; // sucesso se preencher exatamente 'length' bytes
}

int main() {

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

    int comp_msg = 46;
    unsigned char encrypted[comp_msg];
    unsigned char data[comp_msg+1];
    unsigned char tag[16];    
    int res;

    HANDLE hSerial = init_serial("COM4");  
    if (hSerial == INVALID_HANDLE_VALUE) return 1;

    unsigned char buffer[577];
    unsigned char str[comp_msg];

    memset(buffer, 0, sizeof(buffer)); 

    DWORD bytesRead;

    printf("Aguardando Mensagem...\n");
    do{
        if (ReadFile(hSerial, buffer, sizeof(buffer), &bytesRead, NULL)) {

            printf("\nbytesRead:\n");
            printf("%d", bytesRead);

            printf("\nMensagem HEX:\n");
            printf("%s", buffer);

            int result = hexstring_to_bytes(buffer, str, comp_msg+16);

            printf("Mensagem:\n");
            for (int i = 0; i < comp_msg + 16; i++) {
                printf("%02X", str[i]);
            } 

            memcpy(encrypted, str, comp_msg);
            memcpy(tag, str + (comp_msg), 16);

            printf("\nDado Encrypted:\n");
            for (int i = 0; i < comp_msg; i++) {
                printf("%02X", encrypted[i]);
            } 
            printf("\nDado tag:\n");
            for (int i = 0; i < 16; i++) {
                printf("%02X", tag[i]);
            } 

            res = AEAD_chacha20_poly1305_receive(key, iv, AAD, sizeof(AAD), encrypted, comp_msg, data, tag);


            if (res) {
                data[comp_msg+1] = '\0';
                printf("\nMensagem Descriptografada: \n%s\n", data);
            } else {
                printf("\nMensagem Adulterada\n");
            }
        }
    }while (res == 1);

    CloseHandle(hSerial);
    return 0;
}
