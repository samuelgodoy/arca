// trng.h

#ifndef TRNG_H
#define TRNG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Inicializa o gerador de números aleatórios.
 * 
 * @return 0 em sucesso, -1 em falha.
 */
int trng_init();

/**
 * Gera números aleatórios.
 * 
 * @param buffer Ponteiro para o buffer onde os números aleatórios serão armazenados.
 * @param size Número de bytes a serem gerados.
 * @return 0 em sucesso, -1 em falha.
 */
int trng_generate(void *buffer, size_t size);

/**
 * Finaliza o gerador de números aleatórios, liberando recursos alocados.
 */
void trng_cleanup();

#ifdef __cplusplus
}
#endif

#endif // TRNG_H
