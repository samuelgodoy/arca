#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define AES_BLOCK_SIZE      16
#define NONCE_SIZE          12
#define POLYVAL_BLOCK_SIZE  16
#define MAX_KEY_LENGTH      32
#define MAX_ROUND_KEYS_SIZE 240  // Maximum for AES-256
                                 // Máximo para AES-256
                                 // Максимум для AES-256
#define AES_MAX_PLAINTEXT_LENGTH (((uint64_t)1 << 36) - 31)

#define AES_KEY_LEN_128 16
#define AES_KEY_LEN_192 24
#define AES_KEY_LEN_256 32

// Rcon for key expansion
// Rcon para expansão de chave
// Rcon для расширения ключа
static const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// Forward declaration of functions used before they are defined
// Declaração antecipada das funções usadas antes de serem definidas
// Предварительное объявление функций, используемых до их определения
void secure_zero_memory(void *v, size_t n);
uint8_t SBOX_Value(uint8_t input);
void SubBytes(uint8_t *state);
void ShiftRows(uint8_t *state);
void MixColumns(uint8_t *state);
static inline uint8_t xtime(uint8_t x);
void AddRoundKey(uint8_t *state, const uint8_t *roundKey);
void KeyExpansion(const uint8_t *key, uint8_t *roundKeys, size_t key_len);
void AES_Encrypt_Block(const uint8_t *key, size_t key_len, const uint8_t *in_block, uint8_t *out_block);
void derive_keys(const uint8_t *key_generating_key, size_t key_generating_key_len, const uint8_t *nonce,
    uint8_t *message_authentication_key, uint8_t *message_encryption_key);
void increment_counter(uint8_t *counter_block);
void AES_CTR(const uint8_t *key, size_t key_len, const uint8_t *initial_counter_block,
    const uint8_t *in, size_t in_len, uint8_t *out);
void POLYVAL(const uint8_t *H, const uint8_t *data, size_t data_len, uint8_t *result);
int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len);
int safe_add_size_t(size_t a, size_t b, size_t *result);
int safe_multiply_size_t(size_t a, size_t b, size_t *result);

// Secure functions for copying and clearing memory
// Funções seguras para copiar e limpar memória
// Безопасные функции для копирования и очистки памяти
int safe_memcpy(void *dest, size_t dest_size, const void *src, size_t count);
int safe_memset(void *dest, int value, size_t count);

// Function to write a 32-bit integer in little-endian format
// Função para escrever um inteiro de 32 bits em formato little-endian
// Функция для записи 32-битного целого числа в формате little-endian
static inline void write_uint32_le(uint32_t value, uint8_t *output) {
    if (output == NULL) {
        return;
    }
    output[0] = (uint8_t)(value & 0xFF);
    output[1] = (uint8_t)((value >> 8) & 0xFF);
    output[2] = (uint8_t)((value >> 16) & 0xFF);
    output[3] = (uint8_t)((value >> 24) & 0xFF);
}

// Function to write a 64-bit integer in little-endian format
// Função para escrever um inteiro de 64 bits em formato little-endian
// Функция для записи 64-битного целого числа в формате little-endian
static inline void write_uint64_le(uint64_t value, uint8_t *output) {
    if (output == NULL) {
        return;
    }
    for (size_t i = 0; i < 8; i++) {
        output[i] = (uint8_t)((value >> (8 * i)) & 0xFF);
    }
}

// XOR operation on blocks
// Operação XOR em blocos
// Операция XOR над блоками
static inline void xor_block(uint8_t *out, const uint8_t *a, const uint8_t *b) {
    if (out == NULL || a == NULL || b == NULL) {
        return;
    }
    for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
        out[i] = a[i] ^ b[i];
    }
}

// ROTATE function replacing the macro
// Função ROTATE substituindo o macro
// Функция ROTATE, заменяющая макрос
static inline uint8_t ROTATE(uint8_t x) {
    return (uint8_t)(((x) << 1) | ((x) >> 7));
}

// Time-constant implementation of the S-box function
// Implementação constante em tempo da função S-box
// Константная по времени реализация функции S-box
uint8_t SBOX_Value(uint8_t input) {
    uint8_t y = input;
    uint8_t p = y;
    const uint8_t q = 0x63;

    // Multiplicative inverse in GF(2^8)
    // Inverso multiplicativo em GF(2^8)
    // Мультипликативное обратное в поле GF(2^8)
    for (int i = 0; i < 4; i++) {
        y = (y << 1) | (y >> 7);
        p ^= y;
    }

    // Affine transformation
    // Transformação afim
    // Аффинное преобразование
    y = p ^ ROTATE(p ^ ROTATE(p ^ ROTATE(p ^ ROTATE(p ^ ROTATE(p ^ ROTATE(p))))));
    return y ^ q;
}

// SubBytes transformation
// Transformação SubBytes
// Преобразование SubBytes
void SubBytes(uint8_t *state) {
    if (state == NULL) {
        return;
    }
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = SBOX_Value(state[i]);
    }
}

// Time-constant ShiftRows function
// Função ShiftRows constante em tempo
// Константная по времени функция ShiftRows
void ShiftRows(uint8_t *state) {
    if (state == NULL) {
        return;
    }
    uint8_t temp_state[AES_BLOCK_SIZE];

    // Copy state to avoid data-dependent accesses
    // Copia o estado para evitar acessos dependentes de dados
    // Копирует состояние, чтобы избежать зависимых от данных доступов
    if (safe_memcpy(temp_state, sizeof(temp_state), state, AES_BLOCK_SIZE) != 0) {
        return; // Error copying memory
                // Erro ao copiar memória
                // Ошибка при копировании памяти
    }

    // Apply ShiftRows operation in an indexed manner
    // Aplica a operação ShiftRows de forma indexada
    // Применяет операцию ShiftRows индексированным способом
    static const uint8_t shift[16] = {
        0, 5, 10, 15,
        4, 9, 14, 3,
        8, 13, 2, 7,
        12, 1, 6, 11
    };

    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = temp_state[shift[i]];
    }

    // Clear sensitive variables
    // Limpeza de variáveis sensíveis
    // Очистка чувствительных переменных
    secure_zero_memory(temp_state, sizeof(temp_state));
}

// Time-constant xtime function
// Função xtime constante em tempo
// Константная по времени функция xtime
static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1B));
}

// Time-constant MixColumns function
// Função MixColumns constante em tempo
// Константная по времени функция MixColumns
void MixColumns(uint8_t *state) {
    if (state == NULL) {
        return;
    }
    uint8_t tmp[AES_BLOCK_SIZE];
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i * 4];
        uint8_t s1 = state[i * 4 + 1];
        uint8_t s2 = state[i * 4 + 2];
        uint8_t s3 = state[i * 4 + 3];

        uint8_t h = s0 ^ s1 ^ s2 ^ s3;

        tmp[i * 4]     = s0 ^ h ^ xtime(s0 ^ s1);
        tmp[i * 4 + 1] = s1 ^ h ^ xtime(s1 ^ s2);
        tmp[i * 4 + 2] = s2 ^ h ^ xtime(s2 ^ s3);
        tmp[i * 4 + 3] = s3 ^ h ^ xtime(s3 ^ s0);
    }
    if (safe_memcpy(state, AES_BLOCK_SIZE, tmp, AES_BLOCK_SIZE) != 0) {
        return; // Error copying memory
                // Erro ao copiar memória
                // Ошибка при копировании памяти
    }

    // Clear sensitive variables
    // Limpeza de variáveis sensíveis
    // Очистка чувствительных переменных
    secure_zero_memory(tmp, sizeof(tmp));
}

// Time-constant AddRoundKey function
// Função AddRoundKey constante em tempo
// Константная по времени функция AddRoundKey
void AddRoundKey(uint8_t *state, const uint8_t *roundKey) {
    if (state == NULL || roundKey == NULL) {
        return;
    }
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= roundKey[i];
    }
}

// Secure memory clearing
// Limpeza segura de memória
// Безопасная очистка памяти
void secure_zero_memory(void *v, size_t n) {
    if (v == NULL) {
        return;
    }
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) {
        *p++ = 0;
    }
}

// Implementation of safe_memcpy
// Implementação de safe_memcpy
// Реализация safe_memcpy
int safe_memcpy(void *dest, size_t dest_size, const void *src, size_t count) {
    if (dest == NULL || src == NULL) {
        return -1;
    }
    if (count > dest_size) {
        return -1; // Prevents buffer overflow
                    // Evita estouro de buffer
                    // Предотвращает переполнение буфера
    }
    memcpy(dest, src, count);
    return 0;
}

// Implementation of safe_memset
// Implementação de safe_memset
// Реализация safe_memset
int safe_memset(void *dest, int value, size_t count) {
    if (dest == NULL) {
        return -1;
    }
    memset(dest, value, count);
    return 0;
}

// Secure key expansion
// Expansão de chave segura
// Безопасное расширение ключа
void KeyExpansion(const uint8_t *key, uint8_t *roundKeys, size_t key_len) {
    if (key == NULL || roundKeys == NULL) {
        return;
    }
    int Nk = key_len / 4;
    int Nr = Nk + 6;

    if (safe_memcpy(roundKeys, MAX_ROUND_KEYS_SIZE, key, key_len) != 0) {
        return; // Error copying key
                // Erro ao copiar chave
                // Ошибка при копировании ключа
    }

    uint32_t temp = 0;
    uint8_t temp_bytes[4] = {0};

    for (int i = Nk; i < 4 * (Nr + 1); i++) {
        memcpy(&temp, &roundKeys[4 * (i - 1)], 4);

        if (i % Nk == 0) {
            // RotWord
            temp = (temp << 8) | (temp >> 24);

            // SubWord
            temp_bytes[0] = SBOX_Value((temp >> 24) & 0xFF);
            temp_bytes[1] = SBOX_Value((temp >> 16) & 0xFF);
            temp_bytes[2] = SBOX_Value((temp >> 8) & 0xFF);
            temp_bytes[3] = SBOX_Value(temp & 0xFF);
            memcpy(&temp, temp_bytes, 4);

            temp ^= ((uint32_t)Rcon[i / Nk]) << 24;
        } else if (Nk > 6 && i % Nk == 4) {
            // SubWord
            temp_bytes[0] = SBOX_Value((temp >> 24) & 0xFF);
            temp_bytes[1] = SBOX_Value((temp >> 16) & 0xFF);
            temp_bytes[2] = SBOX_Value((temp >> 8) & 0xFF);
            temp_bytes[3] = SBOX_Value(temp & 0xFF);
            memcpy(&temp, temp_bytes, 4);
        }

        uint32_t prev_key;
        memcpy(&prev_key, &roundKeys[4 * (i - Nk)], 4);
        temp ^= prev_key;
        if (safe_memcpy(&roundKeys[4 * i], MAX_ROUND_KEYS_SIZE - (4 * i), &temp, 4) != 0) {
            return; // Error copying round key
                    // Erro ao copiar round key
                    // Ошибка при копировании раундового ключа
        }
    }

    // Clear sensitive variables
    // Limpeza de variáveis sensíveis
    // Очистка чувствительных переменных
    secure_zero_memory(&temp, sizeof(temp));
    secure_zero_memory(temp_bytes, sizeof(temp_bytes));
}

// Time-constant AES_Encrypt_Block function
// Função AES_Encrypt_Block constante em tempo
// Константная по времени функция AES_Encrypt_Block
void AES_Encrypt_Block(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *in_block,
    uint8_t *out_block
) {
    if (!key || !in_block || !out_block) {
        return;
    }
    if (key_len != AES_KEY_LEN_128 && key_len != AES_KEY_LEN_192 && key_len != AES_KEY_LEN_256) {
        return;
    }

    uint8_t state[AES_BLOCK_SIZE];
    uint8_t roundKeys[MAX_ROUND_KEYS_SIZE];

    if (safe_memcpy(state, sizeof(state), in_block, AES_BLOCK_SIZE) != 0) {
        return; // Error copying input block
                // Erro ao copiar bloco de entrada
                // Ошибка при копировании входного блока
    }
    KeyExpansion(key, roundKeys, key_len);

    int Nr = (key_len / 4) + 6;

    AddRoundKey(state, roundKeys);

    for (int round = 1; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * AES_BLOCK_SIZE);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * AES_BLOCK_SIZE);

    if (safe_memcpy(out_block, AES_BLOCK_SIZE, state, AES_BLOCK_SIZE) != 0) {
        return; // Error copying output block
                // Erro ao copiar bloco de saída
                // Ошибка при копировании выходного блока
    }

    // Clear sensitive variables
    // Limpeza de variáveis sensíveis
    // Очистка чувствительных переменных
    secure_zero_memory(state, sizeof(state));
    secure_zero_memory(roundKeys, sizeof(roundKeys));
}

// Time-constant counter increment function
// Função de incremento de contador constante em tempo
// Константная по времени функция увеличения счетчика
void increment_counter(uint8_t *counter_block) {
    if (counter_block == NULL) {
        return;
    }
    uint8_t carry = 1;
    for (int i = 0; i < 4; i++) {
        uint8_t temp = counter_block[i];
        counter_block[i] += carry;
        carry = (counter_block[i] < temp) ? 1 : 0;
    }
}

// Time-constant comparison function
// Função de comparação em tempo constante
// Константная по времени функция сравнения
int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    if (a == NULL || b == NULL) {
        return -1;
    }
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result; // Returns 0 if equal
                   // Retorna 0 se igual
                   // Возвращает 0, если равны
}

// Functions for safe addition and multiplication operations
// Funções para operações seguras de adição e multiplicação
// Функции для безопасных операций сложения и умножения
int safe_add_size_t(size_t a, size_t b, size_t *result) {
    if (result == NULL) {
        return -1;
    }
    if (SIZE_MAX - a < b) {
        return -1; // Overflow
                    // Overflow
                    // Переполнение
    }
    *result = a + b;
    return 0;
}

int safe_multiply_size_t(size_t a, size_t b, size_t *result) {
    if (result == NULL) {
        return -1;
    }
    if (a == 0 || b == 0) {
        *result = 0;
        return 0;
    }
    if (SIZE_MAX / a < b) {
        return -1; // Overflow
                    // Overflow
                    // Переполнение
    }
    *result = a * b;
    return 0;
}

// derive_keys function with input validation
// Função derive_keys com validação de entrada
// Функция derive_keys с проверкой входных данных
void derive_keys(
    const uint8_t *key_generating_key,
    size_t key_generating_key_len,
    const uint8_t *nonce,
    uint8_t *message_authentication_key,
    uint8_t *message_encryption_key
) {
    // Input validation
    // Validação de entrada
    // Проверка входных данных
    if (!key_generating_key || !nonce || !message_authentication_key || !message_encryption_key) {
        return;
    }
    if (key_generating_key_len != AES_KEY_LEN_128 && key_generating_key_len != AES_KEY_LEN_256) {
        return;
    }

    uint8_t input_block[AES_BLOCK_SIZE];
    uint8_t output_block[AES_BLOCK_SIZE] = {0};
    uint32_t counter = 0;

    // Generate message_authentication_key
    // Gera message_authentication_key
    // Генерация message_authentication_key
    for (int i = 0; i < 2; i++) {
        write_uint32_le(counter++, input_block);
        if (safe_memcpy(input_block + 4, AES_BLOCK_SIZE - 4, nonce, NONCE_SIZE) != 0) {
            return; // Error copying nonce
                    // Erro ao copiar nonce
                    // Ошибка при копировании nonce
        }
        AES_Encrypt_Block(key_generating_key, key_generating_key_len, input_block, output_block);
        if (safe_memcpy(message_authentication_key + i * 8, 16 - i * 8, output_block, 8) != 0) {
            return; // Error copying key
                    // Erro ao copiar chave
                    // Ошибка при копировании ключа
        }
    }

    // Generate message_encryption_key
    // Gera message_encryption_key
    // Генерация message_encryption_key
    size_t num_blocks = (key_generating_key_len == AES_KEY_LEN_128) ? 2 : 4;
    for (size_t i = 0; i < num_blocks; i++) {
        write_uint32_le(counter++, input_block);
        if (safe_memcpy(input_block + 4, AES_BLOCK_SIZE - 4, nonce, NONCE_SIZE) != 0) {
            return; // Error copying nonce
                    // Erro ao copiar nonce
                    // Ошибка при копировании nonce
        }
        AES_Encrypt_Block(key_generating_key, key_generating_key_len, input_block, output_block);
        if (safe_memcpy(message_encryption_key + i * 8, MAX_KEY_LENGTH - i * 8, output_block, 8) != 0) {
            return; // Error copying key
                    // Erro ao copiar chave
                    // Ошибка при копировании ключа
        }
    }

    // Clear sensitive variables
    // Limpeza de variáveis sensíveis
    // Очистка чувствительных переменных
    secure_zero_memory(input_block, sizeof(input_block));
    secure_zero_memory(output_block, sizeof(output_block));
}

// AES_CTR function with input validation
// Função AES_CTR com validação de entrada
// Функция AES_CTR с проверкой входных данных
void AES_CTR(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *initial_counter_block,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out
) {
    // Input validation
    // Validação de entrada
    // Проверка входных данных
    if (!key || !initial_counter_block || !in || !out) {
        return;
    }
    if (key_len != AES_KEY_LEN_128 && key_len != AES_KEY_LEN_192 && key_len != AES_KEY_LEN_256) {
        return;
    }

    uint8_t counter_block[AES_BLOCK_SIZE];
    uint8_t keystream_block[AES_BLOCK_SIZE];
    if (safe_memcpy(counter_block, sizeof(counter_block), initial_counter_block, AES_BLOCK_SIZE) != 0) {
        return; // Error copying counter block
                // Erro ao copiar counter block
                // Ошибка при копировании блока счетчика
    }

    size_t offset = 0;
    while (offset < in_len) {
        AES_Encrypt_Block(key, key_len, counter_block, keystream_block);

        size_t block_size = ((in_len - offset) > AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (in_len - offset);
        for (size_t i = 0; i < block_size; i++) {
            out[offset + i] = in[offset + i] ^ keystream_block[i];
        }

        increment_counter(counter_block);
        offset += block_size;
    }

    // Clear sensitive variables
    // Limpeza de variáveis sensíveis
    // Очистка чувствительных переменных
    secure_zero_memory(counter_block, sizeof(counter_block));
    secure_zero_memory(keystream_block, sizeof(keystream_block));
}

// Multiplication in GF(2^128) for POLYVAL
// Multiplicação em GF(2^128) para POLYVAL
// Умножение в поле GF(2^128) для POLYVAL
void gf_mul_polyval(const uint8_t *X, const uint8_t *Y, uint8_t *Z) {
    if (X == NULL || Y == NULL || Z == NULL) {
        return;
    }
    uint8_t V[16];
    uint8_t Z_local[16] = {0};
    if (safe_memcpy(V, sizeof(V), Y, 16) != 0) {
        return; // Error copying Y to V
                // Erro ao copiar Y para V
                // Ошибка при копировании Y в V
    }

    // Process bits from least significant to most significant
    // Processa bits do menos significativo ao mais significativo
    // Обрабатывает биты от наименее значимого к наиболее значимому
    for (int i = 0; i < 128; i++) {
        int byte_index = i / 8;
        int bit_index = i % 8;
        uint8_t mask = -((X[byte_index] >> bit_index) & 1);

        for (int j = 0; j < 16; j++) {
            Z_local[j] ^= V[j] & mask;
        }

        // Multiply V by x in GF(2^128)
        // Multiplica V por x em GF(2^128)
        // Умножает V на x в поле GF(2^128)
        uint8_t carry = V[15] & 1;
        for (int j = 15; j > 0; j--) {
            V[j] = (V[j] >> 1) | (V[j - 1] << 7);
        }
        V[0] >>= 1;

        // Apply reduction if carry is set
        // Aplica redução se carry estiver definido
        // Применяет редукцию, если carry установлен
        uint8_t mask_reduction = -(carry & 1);
        V[0] ^= 0xe1 & mask_reduction;
    }
    if (safe_memcpy(Z, 16, Z_local, 16) != 0) {
        return; // Error copying Z_local to Z
                // Erro ao copiar Z_local para Z
                // Ошибка при копировании Z_local в Z
    }

    // Clear sensitive variables
    // Limpeza de variáveis sensíveis
    // Очистка чувствительных переменных
    secure_zero_memory(V, sizeof(V));
    secure_zero_memory(Z_local, sizeof(Z_local));
}

// POLYVAL function
// Função POLYVAL
// Функция POLYVAL
void POLYVAL(const uint8_t *H, const uint8_t *data, size_t data_len, uint8_t *result) {
    if (H == NULL || data == NULL || result == NULL) {
        return;
    }
    uint8_t S[16] = {0};
    size_t blocks = data_len / 16;

    for (size_t i = 0; i < blocks; i++) {
        xor_block(S, S, data + i * 16);
        gf_mul_polyval(S, H, S);
    }

    size_t remaining = data_len % 16;
    if (remaining > 0) {
        uint8_t last_block[16] = {0};
        if (safe_memcpy(last_block, sizeof(last_block), data + blocks * 16, remaining) != 0) {
            return; // Error copying final block
                    // Erro ao copiar bloco final
                    // Ошибка при копировании последнего блока
        }
        xor_block(S, S, last_block);
        gf_mul_polyval(S, H, S);
        // Clear sensitive variables
        // Limpeza de variáveis sensíveis
        // Очистка чувствительных переменных
        secure_zero_memory(last_block, sizeof(last_block));
    }
    if (safe_memcpy(result, 16, S, 16) != 0) {
        return; // Error copying result
                // Erro ao copiar resultado
                // Ошибка при копировании результата
    }

    // Clear sensitive variables
    // Limpeza de variáveis sensíveis
    // Очистка чувствительных переменных
    secure_zero_memory(S, sizeof(S));
}

// AES-GCM-SIV encryption function with side-channel attack protections
// Função AES-GCM-SIV de criptografia com proteções contra ataques de canal lateral
// Функция шифрования AES-GCM-SIV с защитой от атак побочных каналов
int aes_gcm_siv_encrypt(
    const uint8_t *key_generating_key,
    size_t key_generating_key_len,
    const uint8_t *nonce,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *ciphertext, // Output: ciphertext + tag
    size_t *ciphertext_len
) {
    if (!key_generating_key || !nonce || !plaintext || !ciphertext || !ciphertext_len) {
        return -1; // Invalid input
                   // Entrada inválida
                   // Неверный ввод
    }
    if (key_generating_key_len != AES_KEY_LEN_128 && key_generating_key_len != AES_KEY_LEN_256) {
        return -1; // Invalid key size
                   // Tamanho de chave inválido
                   // Неверный размер ключа
    }
    if (plaintext_len > AES_MAX_PLAINTEXT_LENGTH || aad_len > AES_MAX_PLAINTEXT_LENGTH) {
        return -1; // Lengths exceed limits
                   // Comprimentos excedem os limites
                   // Длины превышают пределы
    }

    uint8_t message_authentication_key[16];
    uint8_t message_encryption_key[MAX_KEY_LENGTH];

    derive_keys(key_generating_key, key_generating_key_len, nonce, message_authentication_key, message_encryption_key);

    uint8_t H[16] = {0};
    AES_Encrypt_Block(message_authentication_key, 16, H, H);

    // Prepare data for POLYVAL
    // Prepara os dados para o POLYVAL
    // Подготовка данных для POLYVAL
    size_t aad_padded_len = ((aad_len + 15) / 16) * 16;
    size_t plaintext_padded_len = ((plaintext_len + 15) / 16) * 16;
    size_t total_polyval_len;

    if (safe_add_size_t(aad_padded_len, plaintext_padded_len, &total_polyval_len) != 0 ||
        safe_add_size_t(total_polyval_len, 16, &total_polyval_len) != 0) {
        return -1; // Overflow detected
                   // Overflow detectado
                   // Обнаружено переполнение
    }

    uint8_t *data_for_polyval = (uint8_t *)calloc(total_polyval_len, 1);
    if (!data_for_polyval) {
        return -1; // Memory allocation failure
                   // Falha na alocação de memória
                   // Сбой при выделении памяти
    }

    // Copy AAD and plaintext
    // Copia AAD e plaintext
    // Копирует AAD и открытый текст
    if (safe_memcpy(data_for_polyval, total_polyval_len, aad, aad_len) != 0 ||
        safe_memcpy(data_for_polyval + aad_padded_len, total_polyval_len - aad_padded_len, plaintext, plaintext_len) != 0) {
        free(data_for_polyval);
        return -1; // Error copying data
                   // Erro ao copiar dados
                   // Ошибка при копировании данных
    }

    // Build length_block
    // Constrói length_block
    // Строит length_block
    uint8_t length_block[16];
    write_uint64_le(aad_len * 8, length_block);
    write_uint64_le(plaintext_len * 8, length_block + 8);

    if (safe_memcpy(data_for_polyval + aad_padded_len + plaintext_padded_len, 16, length_block, 16) != 0) {
        free(data_for_polyval);
        return -1; // Error copying length_block
                   // Erro ao copiar length_block
                   // Ошибка при копировании length_block
    }

    // Calculate S_s
    // Calcula S_s
    // Вычисляет S_s
    uint8_t S_s[16];
    POLYVAL(H, data_for_polyval, total_polyval_len, S_s);

    // Clear and free memory
    // Limpa e libera memória
    // Очищает и освобождает память
    secure_zero_memory(data_for_polyval, total_polyval_len);
    free(data_for_polyval);

    // S_s XOR nonce
    // S_s XOR nonce
    // S_s XOR nonce
    for (int i = 0; i < NONCE_SIZE; i++) {
        S_s[i] ^= nonce[i];
    }
    S_s[15] &= 0x7F; // Clear the most significant bit of the last byte
                     // Limpa o bit mais significativo do último byte
                     // Очищает самый старший бит последнего байта

    // Calculate tag
    // Calcula tag
    // Вычисляет тег
    uint8_t tag[16];
    AES_Encrypt_Block(message_encryption_key, key_generating_key_len, S_s, tag);

    // Prepare counter_block
    // Prepara counter_block
    // Подготавливает counter_block
    uint8_t counter_block[16];
    if (safe_memcpy(counter_block, sizeof(counter_block), tag, 16) != 0) {
        return -1; // Error copying tag to counter_block
                   // Erro ao copiar tag para counter_block
                   // Ошибка при копировании тега в counter_block
    }
    counter_block[15] |= 0x80; // Set the most significant bit of the last byte
                               // Define o bit mais significativo do último byte
                               // Устанавливает самый старший бит последнего байта

    // Encrypt plaintext
    // Criptografa plaintext
    // Шифрует открытый текст
    AES_CTR(message_encryption_key, key_generating_key_len, counter_block, plaintext, plaintext_len, ciphertext);

    // Append tag to the end of ciphertext
    // Anexa tag ao final do ciphertext
    // Добавляет тег в конец шифротекста
    if (safe_memcpy(ciphertext + plaintext_len, 16, tag, 16) != 0) {
        return -1; // Error copying tag to ciphertext
                   // Erro ao copiar tag para ciphertext
                   // Ошибка при копировании тега в шифротекст
    }
    *ciphertext_len = plaintext_len + 16;

    // Clear sensitive data
    // Limpeza de dados sensíveis
    // Очистка чувствительных данных
    secure_zero_memory(message_authentication_key, sizeof(message_authentication_key));
    secure_zero_memory(message_encryption_key, sizeof(message_encryption_key));
    secure_zero_memory(H, sizeof(H));
    secure_zero_memory(S_s, sizeof(S_s));
    secure_zero_memory(counter_block, sizeof(counter_block));
    secure_zero_memory(tag, sizeof(tag));

    return 0; // Success
              // Sucesso
              // Успех
}

// AES-GCM-SIV decryption function with side-channel attack protections
// Função AES-GCM-SIV de descriptografia com proteções contra ataques de canal lateral
// Функция расшифрования AES-GCM-SIV с защитой от атак побочных каналов
int aes_gcm_siv_decrypt(
    const uint8_t *key_generating_key,
    size_t key_generating_key_len,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *plaintext,
    size_t *plaintext_len
) {
    if (!key_generating_key || !nonce || !ciphertext || !plaintext || !plaintext_len) {
        return -1; // Invalid input
                   // Entrada inválida
                   // Неверный ввод
    }
    if (key_generating_key_len != AES_KEY_LEN_128 && key_generating_key_len != AES_KEY_LEN_256) {
        return -1; // Invalid key size
                   // Tamanho de chave inválido
                   // Неверный размер ключа
    }
    if (ciphertext_len < 16 || ciphertext_len > (AES_MAX_PLAINTEXT_LENGTH + 16) || aad_len > AES_MAX_PLAINTEXT_LENGTH) {
        return -1; // Failure
                   // Falha
                   // Сбой
    }

    size_t ct_len = ciphertext_len - 16;
    uint8_t tag[16];
    if (safe_memcpy(tag, sizeof(tag), ciphertext + ct_len, 16) != 0) {
        return -1; // Error copying tag
                   // Erro ao copiar tag
                   // Ошибка при копировании тега
    }

    uint8_t message_authentication_key[16];
    uint8_t message_encryption_key[MAX_KEY_LENGTH];

    derive_keys(key_generating_key, key_generating_key_len, nonce, message_authentication_key, message_encryption_key);

    // Prepare counter_block
    // Prepara counter_block
    // Подготавливает counter_block
    uint8_t counter_block[16];
    if (safe_memcpy(counter_block, sizeof(counter_block), tag, 16) != 0) {
        return -1; // Error copying tag to counter_block
                   // Erro ao copiar tag para counter_block
                   // Ошибка при копировании тега в counter_block
    }
    counter_block[15] |= 0x80; // Set the most significant bit of the last byte
                               // Define o bit mais significativo do último byte
                               // Устанавливает самый старший бит последнего байта

    // Decrypt ciphertext
    // Descriptografa ciphertext
    // Расшифровывает шифротекст
    AES_CTR(message_encryption_key, key_generating_key_len, counter_block, ciphertext, ct_len, plaintext);
    *plaintext_len = ct_len;

    // Prepare data for POLYVAL
    // Prepara dados para POLYVAL
    // Подготавливает данные для POLYVAL
    uint8_t H[16] = {0};
    AES_Encrypt_Block(message_authentication_key, 16, H, H);

    size_t aad_padded_len = ((aad_len + 15) / 16) * 16;
    size_t plaintext_padded_len = ((ct_len + 15) / 16) * 16;
    size_t total_polyval_len;

    if (safe_add_size_t(aad_padded_len, plaintext_padded_len, &total_polyval_len) != 0 ||
        safe_add_size_t(total_polyval_len, 16, &total_polyval_len) != 0) {
        return -1; // Overflow detected
                   // Overflow detectado
                   // Обнаружено переполнение
    }

    uint8_t *data_for_polyval = (uint8_t *)calloc(total_polyval_len, 1);
    if (!data_for_polyval) {
        return -1; // Memory allocation failure
                   // Falha na alocação de memória
                   // Сбой при выделении памяти
    }

    // Copy AAD and plaintext with padding
    // Copia AAD e plaintext com padding
    // Копирует AAD и открытый текст с дополнением
    if (safe_memcpy(data_for_polyval, total_polyval_len, aad, aad_len) != 0 ||
        safe_memcpy(data_for_polyval + aad_padded_len, total_polyval_len - aad_padded_len, plaintext, ct_len) != 0) {
        free(data_for_polyval);
        return -1; // Error copying data
                   // Erro ao copiar dados
                   // Ошибка при копировании данных
    }

    // Build length_block
    // Constrói length_block
    // Строит length_block
    uint8_t length_block[16];
    write_uint64_le(aad_len * 8, length_block);
    write_uint64_le(ct_len * 8, length_block + 8);

    if (safe_memcpy(data_for_polyval + aad_padded_len + plaintext_padded_len, 16, length_block, 16) != 0) {
        free(data_for_polyval);
        return -1; // Error copying length_block
                   // Erro ao copiar length_block
                   // Ошибка при копировании length_block
    }

    // Calculate S_s
    // Calcula S_s
    // Вычисляет S_s
    uint8_t S_s[16];
    POLYVAL(H, data_for_polyval, total_polyval_len, S_s);

    // Clear and free memory
    // Limpa e libera memória
    // Очищает и освобождает память
    secure_zero_memory(data_for_polyval, total_polyval_len);
    free(data_for_polyval);

    // S_s XOR nonce
    for (int i = 0; i < NONCE_SIZE; i++) {
        S_s[i] ^= nonce[i];
    }
    S_s[15] &= 0x7F; // Clear the most significant bit of the last byte
                     // Limpa o bit mais significativo do último byte
                     // Очищает самый старший бит последнего байта

    // Calculate expected tag
    // Calcula tag esperado
    // Вычисляет ожидаемый тег
    uint8_t expected_tag[16];
    AES_Encrypt_Block(message_encryption_key, key_generating_key_len, S_s, expected_tag);

    // Compare tags in constant time
    // Compara tags em tempo constante
    // Сравнивает теги за постоянное время
    if (constant_time_compare(expected_tag, tag, 16) != 0) {
        // Clear plaintext before returning
        // Limpa plaintext antes de retornar
        // Очищает открытый текст перед возвратом
        secure_zero_memory(plaintext, ct_len);

        // Clear sensitive data
        // Limpeza de dados sensíveis
        // Очистка чувствительных данных
        secure_zero_memory(message_authentication_key, sizeof(message_authentication_key));
        secure_zero_memory(message_encryption_key, sizeof(message_encryption_key));
        secure_zero_memory(H, sizeof(H));
        secure_zero_memory(S_s, sizeof(S_s));
        secure_zero_memory(counter_block, sizeof(counter_block));
        secure_zero_memory(expected_tag, sizeof(expected_tag));
        secure_zero_memory(tag, sizeof(tag));

        return -1; // Authentication failure
                   // Falha de autenticação
                   // Ошибка аутентификации
    }

    // Clear sensitive data
    // Limpeza de dados sensíveis
    // Очистка чувствительных данных
    secure_zero_memory(message_authentication_key, sizeof(message_authentication_key));
    secure_zero_memory(message_encryption_key, sizeof(message_encryption_key));
    secure_zero_memory(H, sizeof(H));
    secure_zero_memory(S_s, sizeof(S_s));
    secure_zero_memory(counter_block, sizeof(counter_block));
    secure_zero_memory(expected_tag, sizeof(expected_tag));
    secure_zero_memory(tag, sizeof(tag));

    return 0; // Success
              // Sucesso
              // Успех
}
