
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#ifndef u_int
typedef unsigned int u_int;
#endif

#ifndef u_char
typedef unsigned char u_char;
#endif

#ifndef u_short
typedef unsigned short u_short;
#endif

#include "trng.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
#define OS_WINDOWS
#elif defined(__APPLE__) && defined(__MACH__)
#define OS_MAC
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define OS_BSD
#elif defined(__linux__)
#define OS_LINUX
#else
#define OS_UNIX
#endif


#if defined(__x86_64__) || defined(_M_X64) || defined(__amd64__)
#define ARCH_AMD64
#elif defined(__aarch64__) || defined(_M_ARM64)
#define ARCH_ARM64
#else
#define ARCH_UNKNOWN
#endif

#ifdef OS_WINDOWS
#include <windows.h>
#include <wincrypt.h>
#include <processthreadsapi.h> 
#include <intrin.h>            
static HCRYPTPROV hCryptProv = 0;
#elif defined(OS_BSD) || defined(OS_LINUX) || defined(OS_MAC) || defined(OS_UNIX)
#include <fcntl.h>   
#include <unistd.h>  
#include <pthread.h> 
#include <sys/types.h>
#ifdef OS_LINUX
#include <sys/syscall.h> 
#endif
#ifdef OS_MAC
#include <sys/sysctl.h> 
#endif
#ifdef OS_BSD
#include <sys/sysctl.h> 
#endif
#ifdef ARCH_ARM64
#include <sys/ioctl.h>

#endif
static int entropy_fd = -1;
#endif


typedef struct
{
    unsigned int state[8];
    unsigned long long bitcount;
    unsigned char buffer[64];
} SHA256_CTX;

void sha256_transform(SHA256_CTX *ctx, const unsigned char data[]);
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const unsigned char data[], size_t len);
void sha256_final(SHA256_CTX *ctx, unsigned char hash[]);


static const unsigned int K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};


void sha256_init(SHA256_CTX *ctx)
{
    ctx->bitcount = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}


#define ROTRIGHT(word, bits) (((word) >> (bits)) | ((word) << (32 - (bits))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

void sha256_transform(SHA256_CTX *ctx, const unsigned char data[])
{
    unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i)
    {
        
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_update(SHA256_CTX *ctx, const unsigned char data[], size_t len)
{
    size_t i = 0;

    for (i = 0; i < len; ++i)
    {
        ctx->buffer[ctx->bitcount / 8 % 64] = data[i];
        ctx->bitcount += 8;
        if ((ctx->bitcount / 8) % 64 == 0)
            sha256_transform(ctx, ctx->buffer);
    }
}

void sha256_final(SHA256_CTX *ctx, unsigned char hash[])
{
    unsigned int i = ctx->bitcount / 8 % 64;

    ctx->buffer[i++] = 0x80;
    if (i > 56)
    {
        while (i < 64)
            ctx->buffer[i++] = 0x00;
        sha256_transform(ctx, ctx->buffer);
        i = 0;
    }
    while (i < 56)
        ctx->buffer[i++] = 0x00;

    
    unsigned long long bitcount = ctx->bitcount;
    ctx->buffer[56] = (bitcount >> 56) & 0xFF;
    ctx->buffer[57] = (bitcount >> 48) & 0xFF;
    ctx->buffer[58] = (bitcount >> 40) & 0xFF;
    ctx->buffer[59] = (bitcount >> 32) & 0xFF;
    ctx->buffer[60] = (bitcount >> 24) & 0xFF;
    ctx->buffer[61] = (bitcount >> 16) & 0xFF;
    ctx->buffer[62] = (bitcount >> 8) & 0xFF;
    ctx->buffer[63] = bitcount & 0xFF;
    sha256_transform(ctx, ctx->buffer);

    
    for (i = 0; i < 4; ++i)
    {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0xFF;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xFF;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xFF;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xFF;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xFF;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xFF;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xFF;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xFF;
    }
}


int get_extra_entropy(void *buffer, size_t size)
{
    unsigned char *buf = (unsigned char *)buffer;
    size_t i = 0;
    SHA256_CTX sha_ctx;
    unsigned char hash[32];

    
    sha256_init(&sha_ctx);

    
    struct timespec ts;
#if defined(OS_WINDOWS)
    
    
    LARGE_INTEGER frequency_win, counter_win;
    if (QueryPerformanceFrequency(&frequency_win) && QueryPerformanceCounter(&counter_win))
    {
        ts.tv_sec = (time_t)(counter_win.QuadPart / frequency_win.QuadPart);
        ts.tv_nsec = (long)((counter_win.QuadPart % frequency_win.QuadPart) * 1000000000LL / frequency_win.QuadPart);
        sha256_update(&sha_ctx, (unsigned char *)&ts, sizeof(ts));
        i += sizeof(ts);
    }

    
    typedef VOID(WINAPI * GetSystemTimePreciseAsFileTimeFunc)(LPFILETIME);
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32)
    {
        GetSystemTimePreciseAsFileTimeFunc GetPreciseTime =
            (GetSystemTimePreciseAsFileTimeFunc)GetProcAddress(hKernel32, "GetSystemTimePreciseAsFileTime");
        if (GetPreciseTime)
        {
            FILETIME precise_time;
            GetPreciseTime(&precise_time);
            sha256_update(&sha_ctx, (unsigned char *)&precise_time, sizeof(precise_time));
            i += sizeof(precise_time);
        }
    }
#else
    
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
    {
        sha256_update(&sha_ctx, (unsigned char *)&ts, sizeof(ts));
        i += sizeof(ts);
    }

    
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    {
        sha256_update(&sha_ctx, (unsigned char *)&ts, sizeof(ts));
        i += sizeof(ts);
    }
#endif


#ifdef OS_WINDOWS
    DWORD pid = GetCurrentProcessId();
    sha256_update(&sha_ctx, (unsigned char *)&pid, sizeof(pid));
    i += sizeof(pid);
#else
    pid_t pid = getpid();
    sha256_update(&sha_ctx, (unsigned char *)&pid, sizeof(pid));
    i += sizeof(pid);
#endif


#ifdef OS_WINDOWS
    DWORD tid = GetCurrentThreadId();
    sha256_update(&sha_ctx, (unsigned char *)&tid, sizeof(tid));
    i += sizeof(tid);
#elif defined(OS_LINUX)
    pid_t tid = syscall(SYS_gettid);
    sha256_update(&sha_ctx, (unsigned char *)&tid, sizeof(tid));
    i += sizeof(tid);
#else
    pthread_t tid = pthread_self();
    sha256_update(&sha_ctx, (unsigned char *)&tid, sizeof(tid));
    i += sizeof(tid);
#endif

    
    void *addr1 = (void *)&addr1;
    sha256_update(&sha_ctx, (unsigned char *)&addr1, sizeof(addr1));
    i += sizeof(addr1);

    void *addr2 = (void *)&get_extra_entropy;
    sha256_update(&sha_ctx, (unsigned char *)&addr2, sizeof(addr2));
    i += sizeof(addr2);

    
    volatile unsigned long long op_counter = 0; 
    for (int j = 0; j < 1000; j++)
    {
        op_counter += j * j;
    }
    sha256_update(&sha_ctx, (unsigned char *)&op_counter, sizeof(op_counter));
    i += sizeof(op_counter);


#ifdef OS_LINUX
    
    FILE *temp_fp = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
    if (temp_fp)
    {
        char temp_str[16];
        if (fgets(temp_str, sizeof(temp_str), temp_fp))
        {
            int temp = atoi(temp_str);
            sha256_update(&sha_ctx, (unsigned char *)&temp, sizeof(temp));
            i += sizeof(temp);
        }
        fclose(temp_fp);
    }

    
    FILE *net_fp = fopen("/proc/net/dev", "rb");
    if (net_fp)
    {
        char net_stat[512];
        size_t net_read_len = fread(net_stat, 1, sizeof(net_stat) - 1, net_fp);
        net_stat[net_read_len] = '\0';
        sha256_update(&sha_ctx, (unsigned char *)net_stat, net_read_len);
        fclose(net_fp);
        i += net_read_len;
    }

    
    FILE *cpu_fp = fopen("/proc/stat", "rb");
    if (cpu_fp)
    {
        char cpu_stat[256];
        size_t cpu_read_len = fread(cpu_stat, 1, sizeof(cpu_stat) - 1, cpu_fp);
        cpu_stat[cpu_read_len] = '\0';
        sha256_update(&sha_ctx, (unsigned char *)cpu_stat, cpu_read_len);
        fclose(cpu_fp);
        i += cpu_read_len;
    }

#elif defined(OS_MAC)
    
    struct timeval boottime;
    size_t len = sizeof(boottime);
    if (sysctlbyname("kern.boottime", &boottime, &len, NULL, 0) == 0)
    {
        sha256_update(&sha_ctx, (unsigned char *)&boottime, sizeof(boottime));
        i += sizeof(boottime);
    }
#elif defined(OS_BSD)
    
    struct timeval boottime_bsd;
    size_t len_bsd = sizeof(boottime_bsd);
    if (sysctlbyname("kern.boottime", &boottime_bsd, &len_bsd, NULL, 0) == 0)
    {
        sha256_update(&sha_ctx, (unsigned char *)&boottime_bsd, sizeof(boottime_bsd));
        i += sizeof(boottime_bsd);
    }
#endif


#ifdef OS_LINUX
    FILE *sensor_fp = fopen("/sys/class/hwmon/hwmon0/temp1_input", "r");
    if (sensor_fp)
    {
        char sensor_str[16];
        if (fgets(sensor_str, sizeof(sensor_str), sensor_fp))
        {
            int sensor = atoi(sensor_str);
            sha256_update(&sha_ctx, (unsigned char *)&sensor, sizeof(sensor));
            i += sizeof(sensor);
        }
        fclose(sensor_fp);
    }
#endif


#ifdef ARCH_AMD64
#if defined(OS_WINDOWS) && defined(_MSC_VER)
    
    int rdrand_val;
    if (__rdseed32_step(&rdrand_val))
    {
        sha256_update(&sha_ctx, (unsigned char *)&rdrand_val, sizeof(rdrand_val));
        i += sizeof(rdrand_val);
    }
#elif (defined(__GNUC__) || defined(__clang__)) && defined(ARCH_AMD64)
    
    unsigned int rdrand_val;
    unsigned char success = 0;
    __asm__ volatile(
        "rdseed %0;"
        : "=r"(rdrand_val), "=qm"(success));
    if (success)
    {
        sha256_update(&sha_ctx, (unsigned char *)&rdrand_val, sizeof(rdrand_val));
        i += sizeof(rdrand_val);
    }
#endif
#endif


#ifdef ARCH_ARM64
    
    
    
#endif

    
    sha256_final(&sha_ctx, hash);

    
    size_t hash_len = sizeof(hash);
    size_t copy_size = size < hash_len ? size : hash_len;
    memcpy(buf, hash, copy_size);
    i += copy_size;

    
    while (i < size)
    {
        size_t remaining = size - i;
        size_t to_copy = remaining < hash_len ? remaining : hash_len;
        memcpy(buf + i, hash, to_copy);
        i += to_copy;
    }

    return 0;
}


int combine_entropy(void *system_entropy, void *extra_entropy, void *output, size_t size)
{
    SHA256_CTX sha_ctx;
    unsigned char hash1[32];
    unsigned char hash2[32];

    
    sha256_init(&sha_ctx);

    
    sha256_update(&sha_ctx, (unsigned char *)system_entropy, size);
    sha256_final(&sha_ctx, hash1);

    
    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, (unsigned char *)extra_entropy, size);
    sha256_final(&sha_ctx, hash2);

    
    unsigned char combined_hash[32];
    for (size_t i = 0; i < 32; i++)
    {
        combined_hash[i] = hash1[i] ^ hash2[i];
    }

    
    size_t combined_len = sizeof(combined_hash);
    size_t copied = 0;
    while (copied < size)
    {
        size_t to_copy = (size - copied) < combined_len ? (size - copied) : combined_len;
        memcpy((unsigned char *)output + copied, combined_hash, to_copy);
        copied += to_copy;
    }

    return 0;
}


int trng_init()
{
#ifdef OS_WINDOWS
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        fprintf(stderr, "Erro ao inicializar provedor criptográfico.\n");
        return -1;
    }
    return 0;

#elif defined(OS_BSD) || defined(OS_LINUX) || defined(OS_MAC) || defined(OS_UNIX)
#if defined(OS_BSD) && !defined(OS_MAC)
    
    
    return 0;
#else
    
    entropy_fd = open("/dev/urandom", O_RDONLY);
    if (entropy_fd < 0)
    {
        perror("Erro ao abrir /dev/urandom");
        return -1;
    }
    return 0;
#endif

#else
    fprintf(stderr, "Sistema operacional não suportado.\n");
    return -1;
#endif
}


int trng_generate(void *buffer, size_t size)
{
    if (buffer == NULL || size == 0)
    {
        fprintf(stderr, "Buffer inválido ou tamanho zero.\n");
        return -1;
    }

    unsigned char *system_entropy = malloc(size);
    if (!system_entropy)
    {
        fprintf(stderr, "Erro ao alocar memória para system_entropy.\n");
        return -1;
    }

    unsigned char *extra_entropy_buffer = malloc(size);
    if (!extra_entropy_buffer)
    {
        fprintf(stderr, "Erro ao alocar memória para extra_entropy_buffer.\n");
        free(system_entropy);
        return -1;
    }

    unsigned char *combined_entropy = malloc(size);
    if (!combined_entropy)
    {
        fprintf(stderr, "Erro ao alocar memória para combined_entropy.\n");
        free(system_entropy);
        free(extra_entropy_buffer);
        return -1;
    }

#ifdef OS_WINDOWS
    if (!CryptGenRandom(hCryptProv, (DWORD)size, system_entropy))
    {
        fprintf(stderr, "Erro ao gerar números aleatórios.\n");
        free(system_entropy);
        free(extra_entropy_buffer);
        free(combined_entropy);
        return -1;
    }

#elif defined(OS_BSD)
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(OS_MAC)
    
    arc4random_buf(system_entropy, size);
#else
    
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        perror("Erro ao abrir /dev/urandom em fallback");
        free(system_entropy);
        free(extra_entropy_buffer);
        free(combined_entropy);
        return -1;
    }
    if (read(fd, system_entropy, size) != (ssize_t)size)
    {
        perror("Erro ao ler /dev/urandom em fallback");
        close(fd);
        free(system_entropy);
        free(extra_entropy_buffer);
        free(combined_entropy);
        return -1;
    }
    close(fd);
#endif

#elif defined(OS_LINUX) || defined(OS_MAC) || defined(OS_UNIX)
    if (entropy_fd < 0)
    {
        fprintf(stderr, "Fonte de entropia não inicializada.\n");
        free(system_entropy);
        free(extra_entropy_buffer);
        free(combined_entropy);
        return -1;
    }
    ssize_t read_bytes = read(entropy_fd, system_entropy, size);
    if (read_bytes != (ssize_t)size)
    {
        perror("Erro ao ler /dev/urandom");
        free(system_entropy);
        free(extra_entropy_buffer);
        free(combined_entropy);
        return -1;
    }

#else
    free(system_entropy);
    free(extra_entropy_buffer);
    free(combined_entropy);
    return -1;
#endif

    
    if (get_extra_entropy(extra_entropy_buffer, size) != 0)
    {
        fprintf(stderr, "Erro ao obter entropia extra.\n");
        free(system_entropy);
        free(extra_entropy_buffer);
        free(combined_entropy);
        return -1;
    }

    
    if (combine_entropy(system_entropy, extra_entropy_buffer, combined_entropy, size) != 0)
    {
        fprintf(stderr, "Erro ao combinar as fontes de entropia.\n");
        free(system_entropy);
        free(extra_entropy_buffer);
        free(combined_entropy);
        return -1;
    }

    
    memcpy(buffer, combined_entropy, size);

    
    memset(system_entropy, 0, size);
    memset(extra_entropy_buffer, 0, size);
    memset(combined_entropy, 0, size);
    free(system_entropy);
    free(extra_entropy_buffer);
    free(combined_entropy);

    return 0;
}


void trng_cleanup()
{
#ifdef OS_WINDOWS
    if (hCryptProv)
    {
        CryptReleaseContext(hCryptProv, 0);
        hCryptProv = 0;
    }

#elif defined(OS_BSD) || defined(OS_LINUX) || defined(OS_MAC) || defined(OS_UNIX)
#if defined(OS_BSD) && !defined(OS_MAC)
    
#else
    if (entropy_fd >= 0)
    {
        close(entropy_fd);
        entropy_fd = -1;
    }
#endif
#endif
}
