#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file aes.h
 * @brief Interface for AES-GCM-SIV encryption operations.
 *        | Interface para operações de criptografia AES-GCM-SIV.
 *        | Интерфейс для операций шифрования AES-GCM-SIV.
 *
 * This file contains definitions, declarations, and documentation of functions related
 * to encryption and decryption using the AES-GCM-SIV mode.
 *        | Este arquivo contém definições, declarações e documentações de funções relacionadas
 *          à criptografia e descriptografia usando o modo AES-GCM-SIV.
 *        | Этот файл содержит определения, объявления и документацию функций, связанных
 *          с шифрованием и дешифрованием с использованием режима AES-GCM-SIV.
 */

/* --------------------------------------------------------------------------
 * Constant Definitions
 * | Definições de Constantes
 * | Определения констант
 * -------------------------------------------------------------------------- */

/** AES block size in bytes (128 bits).
 *  | Tamanho do bloco AES em bytes (128 bits).
 *  | Размер блока AES в байтах (128 бит).
 */
#define AES_BLOCK_SIZE      16

/** Nonce size in bytes.
 *  | Tamanho do nonce em bytes.
 *  | Размер nonce в байтах.
 */
#define NONCE_SIZE          12

/** AES-128 key size in bytes (128 bits).
 *  | Tamanho da chave AES-128 em bytes (128 bits).
 *  | Размер ключа AES-128 в байтах (128 бит).
 */
#define AES_KEY_SIZE_128    16

/** AES-256 key size in bytes (256 bits).
 *  | Tamanho da chave AES-256 em bytes (256 bits).
 *  | Размер ключа AES-256 в байтах (256 бит).
 */
#define AES_KEY_SIZE_256    32

/** Maximum supported plaintext size (64 KB).
 *  | Tamanho máximo suportado para texto claro (64 KB).
 *  | Максимальный поддерживаемый размер открытого текста (64 КБ).
 */
#define MAX_PLAINTEXT_SIZE  65536  // 64 KB

/** Maximum supported additional authenticated data (AAD) size (64 KB).
 *  | Tamanho máximo suportado para dados adicionais autenticados (AAD) (64 KB).
 *  | Максимальный поддерживаемый размер дополнительных аутентифицированных данных (AAD) (64 КБ).
 */
#define MAX_AAD_SIZE        65536  // 64 KB

/* --------------------------------------------------------------------------
 * Data Types
 * | Tipos de Dados
 * | Типы данных
 * -------------------------------------------------------------------------- */

/**
 * @brief Enumeration for AES-GCM-SIV function error codes.
 *        | Enumerador para códigos de erro das funções AES-GCM-SIV.
 *        | Перечисление кодов ошибок функций AES-GCM-SIV.
 */
typedef enum {
    AES_SUCCESS = 0,               /**< Operation completed successfully.
                                    | Operação realizada com sucesso.
                                    | Операция успешно завершена.
                                    */
    AES_ERROR_INVALID_KEY,         /**< Invalid key provided.
                                    | Chave inválida fornecida.
                                    | Предоставлен недопустимый ключ.
                                    */
    AES_ERROR_INVALID_NONCE,       /**< Invalid nonce provided.
                                    | Nonce inválido fornecido.
                                    | Предоставлен недопустимый nonce.
                                    */
    AES_ERROR_INVALID_LENGTH,      /**< Invalid input length.
                                    | Tamanho de entrada inválido.
                                    | Недопустимая длина входных данных.
                                    */
    AES_ERROR_ENCRYPTION_FAILED,   /**< Encryption failed.
                                    | Falha na criptografia.
                                    | Ошибка шифрования.
                                    */
    AES_ERROR_DECRYPTION_FAILED    /**< Decryption failed.
                                    | Falha na descriptografia.
                                    | Ошибка расшифрования.
                                    */
} AES_Result;

/* --------------------------------------------------------------------------
 * Function Declarations
 * | Declarações de Funções
 * | Объявления функций
 * -------------------------------------------------------------------------- */

/**
 * @brief Encrypts data using AES-GCM-SIV.
 *        | Criptografa os dados usando AES-GCM-SIV.
 *        | Шифрует данные с использованием AES-GCM-SIV.
 *
 * @param[in] key_generating_key Key generating key.
 *                                | Chave de geração de chaves.
 *                                | Ключ для генерации ключей.
 * @param[in] key_generating_key_len Length of the key generating key (16 or 32 bytes).
 *                                   | Tamanho da chave de geração (16 ou 32 bytes).
 *                                   | Длина ключа генерации (16 или 32 байта).
 * @param[in] nonce Unique value for each encryption operation.
 *                  | Valor único para cada operação de criptografia.
 *                  | Уникальное значение для каждой операции шифрования.
 * @param[in] plaintext Data to be encrypted.
 *                      | Dados a serem criptografados.
 *                      | Данные для шифрования.
 * @param[in] plaintext_len Length of data to be encrypted (maximum MAX_PLAINTEXT_SIZE).
 *                          | Tamanho dos dados a serem criptografados (máximo MAX_PLAINTEXT_SIZE).
 *                          | Длина данных для шифрования (максимум MAX_PLAINTEXT_SIZE).
 * @param[in] aad Additional authenticated data (optional).
 *                | Dados adicionais autenticados (opcional).
 *                | Дополнительные аутентифицированные данные (необязательно).
 * @param[in] aad_len Length of additional authenticated data (maximum MAX_AAD_SIZE).
 *                    | Tamanho dos dados adicionais autenticados (máximo MAX_AAD_SIZE).
 *                    | Длина дополнительных аутентифицированных данных (максимум MAX_AAD_SIZE).
 * @param[out] ciphertext Output buffer containing the ciphertext followed by the tag.
 *                        | Buffer de saída contendo o texto cifrado seguido da tag.
 *                        | Выходной буфер, содержащий шифротекст, за которым следует тег.
 * @param[out] ciphertext_len Pointer to the resulting ciphertext length.
 *                            | Ponteiro para o tamanho do texto cifrado resultante.
 *                            | Указатель на полученную длину шифротекста.
 *
 * @return AES_Result Operation status code.
 *                    | Código de status da operação.
 *                    | Код состояния операции.
 */
AES_Result aes_gcm_siv_encrypt(
    const uint8_t *key_generating_key,
    size_t key_generating_key_len,
    const uint8_t *nonce,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *ciphertext,
    size_t *ciphertext_len
);

/**
 * @brief Decrypts data using AES-GCM-SIV.
 *        | Descriptografa os dados usando AES-GCM-SIV.
 *        | Дешифрует данные с использованием AES-GCM-SIV.
 *
 * @param[in] key_generating_key Key generating key.
 *                                | Chave de geração de chaves.
 *                                | Ключ для генерации ключей.
 * @param[in] key_generating_key_len Length of the key generating key (16 or 32 bytes).
 *                                   | Tamanho da chave de geração (16 ou 32 bytes).
 *                                   | Длина ключа генерации (16 или 32 байта).
 * @param[in] nonce Unique value associated with the ciphertext.
 *                  | Valor único associado ao texto cifrado.
 *                  | Уникальное значение, связанное с шифротекстом.
 * @param[in] ciphertext Ciphertext followed by the tag.
 *                       | Texto cifrado seguido da tag.
 *                       | Шифротекст, за которым следует тег.
 * @param[in] ciphertext_len Length of the ciphertext.
 *                           | Tamanho do texto cifrado.
 *                           | Длина шифротекста.
 * @param[in] aad Additional authenticated data used during encryption (optional).
 *                | Dados adicionais autenticados usados na criptografia (opcional).
 *                | Дополнительные аутентифицированные данные, использованные при шифровании (необязательно).
 * @param[in] aad_len Length of additional authenticated data.
 *                    | Tamanho dos dados adicionais autenticados.
 *                    | Длина дополнительных аутентифицированных данных.
 * @param[out] plaintext Output buffer for decrypted data.
 *                       | Buffer de saída para os dados descriptografados.
 *                       | Выходной буфер для расшифрованных данных.
 * @param[out] plaintext_len Pointer to the resulting decrypted data length.
 *                           | Ponteiro para o tamanho dos dados descriptografados resultantes.
 *                           | Указатель на полученную длину расшифрованных данных.
 *
 * @return AES_Result Operation status code.
 *                    | Código de status da operação.
 *                    | Код состояния операции.
 */
AES_Result aes_gcm_siv_decrypt(
    const uint8_t *key_generating_key,
    size_t key_generating_key_len,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *plaintext,
    size_t *plaintext_len
);

/**
 * @brief Encrypts a single 16-byte block using AES.
 *        | Realiza a criptografia de um único bloco de 16 bytes usando AES.
 *        | Выполняет шифрование одного 16-байтового блока с использованием AES.
 *
 * @param[in] key Encryption key.
 *                | Chave de criptografia.
 *                | Ключ шифрования.
 * @param[in] key_len Length of the key (16 or 32 bytes).
 *                    | Tamanho da chave (16 ou 32 bytes).
 *                    | Длина ключа (16 или 32 байта).
 * @param[in] in_block Input block (16 bytes).
 *                     | Bloco de entrada (16 bytes).
 *                     | Входной блок (16 байт).
 * @param[out] out_block Encrypted output block (16 bytes).
 *                       | Bloco de saída criptografado (16 bytes).
 *                       | Зашифрованный выходной блок (16 байт).
 */
void AES_Encrypt_Block(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *in_block,
    uint8_t *out_block
);

/* --------------------------------------------------------------------------
 * Implementation Notes
 * | Notas de Implementação
 * | Примечания по реализации
 * -------------------------------------------------------------------------- */

/**
 * - All functions check input sizes and return appropriate errors.
 *   | Todas as funções verificam os tamanhos de entrada e retornam erros adequados.
 *   | Все функции проверяют размеры входных данных и возвращают соответствующие ошибки.
 *
 * - Functions do not perform dynamic allocations; the caller is responsible for providing appropriate buffers.
 *   | As funções não realizam alocações dinâmicas; o chamador é responsável por fornecer buffers apropriados.
 *   | Функции не выполняют динамического выделения памяти; вызывающая сторона должна предоставить соответствующие буферы.
 *
 * - The `nonce` must be unique for each encrypted message to ensure security.
 *   | O `nonce` deve ser único para cada mensagem criptografada para garantir a segurança.
 *   | `nonce` должен быть уникальным для каждого зашифрованного сообщения для обеспечения безопасности.
 *
 * - Functions are optimized to avoid common vulnerabilities such as buffer overflows.
 *   | Funções são otimizadas para evitar vulnerabilidades comuns, como estouros de buffer.
 *   | Функции оптимизированы для предотвращения распространенных уязвимостей, таких как переполнение буфера.
 */

#endif // AES_H