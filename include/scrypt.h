#ifndef SCRYPT_H
#define SCRYPT_H

#include <stdint.h>
#include <stddef.h>

int scrypt(const uint8_t *pw, size_t pwl, const uint8_t *s, size_t sl,
           uint64_t N, uint32_t r, uint32_t p, uint8_t *buf, size_t buflen);

#endif // SCRYPT_H
