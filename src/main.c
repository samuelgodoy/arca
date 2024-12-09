#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <getopt.h>
#include <locale.h>

#include "aes.h"
#include "scrypt.h"
#include "trng.h"
#include "mensagens.h"

#if defined(_WIN32) || defined(_WIN64)
#include <conio.h>
#else
#include <termios.h>
#endif

#define SALT_SIZE 16
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define ASSOCIATED_DATA "arca"
#define SCRYPT_N 16384
#define SCRYPT_R 14
#define SCRYPT_P 14
#define DEFAULT_BINARY_FILE "arca.bin"


#define HANDLE_ERROR(msg)             \
    {                                 \
        fprintf(stderr, "%s\n", msg); \
        trng_cleanup();               \
        exit(EXIT_FAILURE);           \
    }

typedef struct
{
    uint8_t salt[SALT_SIZE], nonce[NONCE_SIZE], auth_tag[TAG_SIZE];
    size_t ciphertext_len; 
} encrypted_data_t;

typedef struct
{
    uint32_t id;
    char title[100], user[100], secret[256];
} secret_t;

typedef struct
{
    uint32_t num_secrets;
    secret_t secrets[];
} arca_data_t;


static void read_line(const char *prompt, char *buffer, size_t size)
{
    printf(PROMPT_READ_LINE, prompt);
    fflush(stdout);
    if (!fgets(buffer, size, stdin))
        HANDLE_ERROR(ERROR_READ_INPUT);
    buffer[strcspn(buffer, "\n")] = '\0';
}


static int confirm_action(const char *prompt)
{
    char response[10];
    while (1)
    {
        read_line(prompt, response, sizeof(response));
#if defined(LANG_EN)
        if (strcmp(response, "y") == 0 || strcmp(response, "Y") == 0)
            return 1;
        if (strcmp(response, "n") == 0 || strcmp(response, "N") == 0)
            return 0;
#elif defined(LANG_PT_BR)
        if (strcmp(response, "s") == 0 || strcmp(response, "S") == 0)
            return 1;
        if (strcmp(response, "n") == 0 || strcmp(response, "N") == 0)
            return 0;
#elif defined(LANG_RU)
        if (strcmp(response, "д") == 0 || strcmp(response, "Д") == 0)
            return 1;
        if (strcmp(response, "н") == 0 || strcmp(response, "Н") == 0)
            return 0;
#else
        
        if (strcmp(response, "s") == 0 || strcmp(response, "S") == 0)
            return 1;
        if (strcmp(response, "n") == 0 || strcmp(response, "N") == 0)
            return 0;
#endif
        printf(INVALID_RESPONSE);
    }
}


static int derive_key(const char *password, const uint8_t *salt, uint8_t *key)
{
    return scrypt((const uint8_t *)password, strlen(password), salt, SALT_SIZE, SCRYPT_N, SCRYPT_R, SCRYPT_P, key, 32);
}


static uint32_t generate_unique_id()
{
    uint32_t id = 0;
    if (trng_generate((uint8_t *)&id, sizeof(id)) != 0)
    {
        HANDLE_ERROR("Failed to generate a secure random ID");
    }
    return id;
}



static int file_exists(const char *filename)
{
    return access(filename, F_OK) != -1;
}


static arca_data_t *load_arca(const char *filename, const char *password, size_t *arca_size)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        fprintf(stderr, ERROR_FILE_NOT_FOUND, filename);
        return NULL;
    }

    encrypted_data_t enc_data;
    if (fread(&enc_data, sizeof(enc_data), 1, fp) != 1)
    {
        fclose(fp);
        fprintf(stderr, "%s\n", ERROR_LOAD_FAILED);
        return NULL;
    }

    
    if (enc_data.ciphertext_len > (1 << 30))
    { 
        fclose(fp);
        fprintf(stderr, "%s\n", ERROR_LOAD_FAILED);
        return NULL;
    }

    uint8_t *ciphertext = malloc(enc_data.ciphertext_len + TAG_SIZE);
    if (!ciphertext)
    {
        fclose(fp);
        fprintf(stderr, "%s\n", ERROR_LOAD_FAILED);
        return NULL;
    }

    size_t read_bytes = fread(ciphertext, 1, enc_data.ciphertext_len + TAG_SIZE, fp);
    if (read_bytes != (enc_data.ciphertext_len + TAG_SIZE))
    {
        fclose(fp);
        free(ciphertext);
        fprintf(stderr, "%s\n", ERROR_LOAD_FAILED);
        return NULL;
    }
    fclose(fp);

    uint8_t key_derived[32];
    if (derive_key(password, enc_data.salt, key_derived) != 0)
    {
        free(ciphertext);
        fprintf(stderr, "%s\n", ERROR_LOAD_FAILED);
        return NULL;
    }

    uint8_t *decrypted_data = malloc(enc_data.ciphertext_len + 1);
    if (!decrypted_data)
    {
        free(ciphertext);
        fprintf(stderr, "%s\n", ERROR_LOAD_FAILED);
        return NULL;
    }

    int decrypt_result = aes_gcm_siv_decrypt(
        key_derived, sizeof(key_derived), enc_data.nonce, ciphertext, enc_data.ciphertext_len + TAG_SIZE,
        (const uint8_t *)ASSOCIATED_DATA, strlen(ASSOCIATED_DATA), decrypted_data, (size_t *)&enc_data.ciphertext_len);

    free(ciphertext);
    if (decrypt_result != AES_SUCCESS)
    {
        free(decrypted_data);
        fprintf(stderr, "%s\n", ERROR_LOAD_FAILED);
        return NULL;
    }

    
    if (enc_data.ciphertext_len > (1 << 30))
    { 
        free(decrypted_data);
        fprintf(stderr, "%s\n", ERROR_LOAD_FAILED);
        return NULL;
    }

    decrypted_data[enc_data.ciphertext_len] = '\0';
    *arca_size = enc_data.ciphertext_len;
    return (arca_data_t *)decrypted_data;
}


static int save_arca(const char *filename, const char *password, arca_data_t *arca, size_t arca_size)
{
    uint8_t salt[SALT_SIZE], nonce[NONCE_SIZE];
    if (trng_generate(salt, SALT_SIZE) != 0 || trng_generate(nonce, NONCE_SIZE) != 0)
        return -1;

    uint8_t key_derived[32];
    if (derive_key(password, salt, key_derived) != 0)
        return -1;

    size_t ciphertext_len = arca_size + TAG_SIZE;
    uint8_t *ciphertext = malloc(ciphertext_len);
    if (!ciphertext)
        return -1;

    if (aes_gcm_siv_encrypt(
            key_derived, sizeof(key_derived), nonce, (const uint8_t *)arca, arca_size,
            (const uint8_t *)ASSOCIATED_DATA, strlen(ASSOCIATED_DATA), ciphertext, &ciphertext_len) != AES_SUCCESS)
    {
        free(ciphertext);
        return -1;
    }

    encrypted_data_t enc_data = {.ciphertext_len = ciphertext_len - TAG_SIZE};
    memcpy(enc_data.salt, salt, SALT_SIZE);
    memcpy(enc_data.nonce, nonce, NONCE_SIZE);
    memcpy(enc_data.auth_tag, ciphertext + enc_data.ciphertext_len, TAG_SIZE);

    FILE *fp = fopen(filename, "wb");
    if (!fp)
    {
        free(ciphertext);
        return -1;
    }

    
    if (fwrite(&enc_data, sizeof(enc_data), 1, fp) != 1)
    {
        fclose(fp);
        free(ciphertext);
        return -1;
    }

    if (fwrite(ciphertext, 1, ciphertext_len, fp) != ciphertext_len)
    {
        fclose(fp);
        free(ciphertext);
        return -1;
    }

    fclose(fp);
    free(ciphertext);
    return 0;
}

void disable_echo() {
#if defined(_WIN32) || defined(_WIN64)
    
#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_lflag &= ~(ECHO | ICANON); 
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}


void enable_echo() {
#if defined(_WIN32) || defined(_WIN64)
    
#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_lflag |= (ECHO | ICANON); 
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}


void get_secure_input(const char *prompt, char *buffer, size_t buffer_size) {
    printf("%s", prompt);
    fflush(stdout);

    disable_echo();

    size_t idx = 0;
    int ch;

    while (idx < buffer_size - 1) {
#if defined(_WIN32) || defined(_WIN64)
        ch = _getch(); 
#else
        ch = getchar(); 
#endif
        if (ch == '\n' || ch == '\r') {
            break; 
        } else if (ch == 127 || ch == 8) { 
            if (idx > 0) {
                idx--;
                printf("\b \b"); 
                fflush(stdout);
            }
        } else {
            buffer[idx++] = ch;
            printf("*"); 
            fflush(stdout);
        }
    }

    buffer[idx] = '\0'; 
    enable_echo();

    printf("\n");
}


static size_t get_master_password_interactive(const char *prompt, char *password, size_t max_size) {
    char input[max_size];

    get_secure_input(prompt, input, max_size);

    size_t len = strlen(input);
    if (len >= max_size) {
        fprintf(stderr, "Erro: senha excede o tamanho máximo permitido (%zu caracteres)\n", max_size - 1);
        return 0;
    }

    strncpy(password, input, max_size);
    password[max_size - 1] = '\0';

    return len;
}


static void initialize_arca(const char *filename)
{
    if (file_exists(filename) && !confirm_action(PROMPT_CONFIRM_ACTION))
    {
        printf(SUCCESS_CANCELLED);
        return;
    }

    char password[256];
    get_master_password_interactive(PROMPT_MASTER_PASSWORD_CURRENT, password, sizeof(password));

    
    
    arca_data_t *arca = malloc(sizeof(arca_data_t));
    if (!arca)
        HANDLE_ERROR(ERROR_FAILED_TO_INIT_ARCA);
    arca->num_secrets = 0;

    if (save_arca(filename, password, arca, sizeof(arca_data_t)) != 0)
    {
        free(arca);
        HANDLE_ERROR(ERROR_SAVE_FAILED);
    }

    free(arca);
    printf(SUCCESS_INIT_ARCA, filename);
}


static void change_password(const char *filename)
{
    if (!file_exists(filename))
    {
        printf(ERROR_FILE_NOT_FOUND, filename);
        return;
    }

    char old_password[256];
    get_master_password_interactive(PROMPT_MASTER_PASSWORD_CURRENT, old_password, sizeof(old_password));

    size_t arca_size;
    arca_data_t *arca = load_arca(filename, old_password, &arca_size);
    if (!arca)
    {
        printf(ERROR_LOAD_FAILED);
        return;
    }

    char new_password[256];
    get_master_password_interactive(PROMPT_MASTER_PASSWORD_NEW, new_password, sizeof(new_password));

    if (save_arca(filename, new_password, arca, arca_size) != 0)
    {
        free(arca);
        HANDLE_ERROR(ERROR_SAVE_FAILED);
    }

    free(arca);
    printf(SUCCESS_CHANGE_PASSWORD);
}


static void add_secret(const char *filename)
{
    if (!file_exists(filename))
    {
        printf(ERROR_FILE_NOT_FOUND, filename);
        return;
    }

    char password[256];
    get_master_password_interactive(PROMPT_MASTER_PASSWORD_CURRENT, password, sizeof(password));

    size_t arca_size;
    arca_data_t *arca = load_arca(filename, password, &arca_size);
    if (!arca)
    {
        printf(ERROR_LOAD_FAILED);
        return;
    }

    
    size_t new_arca_size = sizeof(arca_data_t) + (arca->num_secrets + 1) * sizeof(secret_t);
    arca = realloc(arca, new_arca_size);
    if (!arca)
    {
        free(arca);
        HANDLE_ERROR(ERROR_FAILED_TO_INIT_ARCA);
    }

    secret_t *new_secret = &arca->secrets[arca->num_secrets];
    new_secret->id = generate_unique_id();

    read_line(PROMPT_LABEL, new_secret->title, sizeof(new_secret->title));
    read_line(PROMPT_LOGIN_OPTIONAL, new_secret->user, sizeof(new_secret->user));
    read_line(PROMPT_SECRET, new_secret->secret, sizeof(new_secret->secret));

    arca->num_secrets += 1;

    if (save_arca(filename, password, arca, new_arca_size) != 0)
    {
        free(arca);
        HANDLE_ERROR(ERROR_SAVE_FAILED);
    }

    free(arca);
    printf(SUCCESS_ADD_SECRET);
}


static void view_secrets(const char *filename)
{
    if (!file_exists(filename))
    {
        printf(ERROR_FILE_NOT_FOUND, filename);
        return;
    }

    char password[256];
    get_master_password_interactive(PROMPT_MASTER_PASSWORD_CURRENT, password, sizeof(password));

    size_t arca_size;
    arca_data_t *arca = load_arca(filename, password, &arca_size);
    if (!arca)
    {
        printf(ERROR_LOAD_FAILED);
        return;
    }

    if (arca->num_secrets == 0)
    {
        printf(ERROR_NO_SECRETS);
        free(arca);
        return;
    }

    for (uint32_t i = 0; i < arca->num_secrets; i++)
    {
        printf("ID: %u | %s %s | %s %s | %s %s\n",
               arca->secrets[i].id,
               PROMPT_LABEL, arca->secrets[i].title,
               PROMPT_LOGIN_OPTIONAL, arca->secrets[i].user,
               PROMPT_SECRET, arca->secrets[i].secret);
    }

    free(arca);
}


static void remove_secret(const char *filename)
{
    if (!file_exists(filename))
    {
        printf(ERROR_FILE_NOT_FOUND, filename);
        return;
    }

    char password[256];
    get_master_password_interactive(PROMPT_MASTER_PASSWORD_CURRENT, password, sizeof(password));

    size_t arca_size;
    arca_data_t *arca = load_arca(filename, password, &arca_size);
    if (!arca)
    {
        printf(ERROR_LOAD_FAILED);
        return;
    }

    if (arca->num_secrets == 0)
    {
        printf(ERROR_NO_SECRETS_TO_REMOVE);
        free(arca);
        return;
    }

    for (uint32_t i = 0; i < arca->num_secrets; i++)
    {
        printf("ID: %u | %s %s\n", arca->secrets[i].id, PROMPT_LABEL, arca->secrets[i].title);
    }

    char id_input[20];
    read_line(PROMPT_REMOVE_ID, id_input, sizeof(id_input));
    uint32_t id = strtoul(id_input, NULL, 10);

    int index = -1;
    for (uint32_t i = 0; i < arca->num_secrets; i++)
    {
        if (arca->secrets[i].id == id)
        {
            index = i;
            break;
        }
    }

    if (index == -1)
    {
        printf(ERROR_ID_NOT_FOUND);
        free(arca);
        return;
    }

    
    memmove(&arca->secrets[index], &arca->secrets[index + 1], (arca->num_secrets - index - 1) * sizeof(secret_t));
    arca->num_secrets -= 1;

    
    size_t new_arca_size = sizeof(arca_data_t) + arca->num_secrets * sizeof(secret_t);
    if (save_arca(filename, password, arca, new_arca_size) != 0)
    {
        free(arca);
        HANDLE_ERROR(ERROR_SAVE_FAILED);
    }

    free(arca);
    printf(SUCCESS_REMOVE_SECRET);
}


static void get_secret(const char *filename, const char *password, uint32_t id)
{
    if (!file_exists(filename))
    {
        fprintf(stderr, ERROR_FILE_NOT_FOUND, filename);
        return;
    }

    size_t arca_size;
    arca_data_t *arca = load_arca(filename, password, &arca_size);
    if (!arca)
    {
        fprintf(stderr, "%s\n", ERROR_LOAD_FAILED);
        return;
    }

    if (arca->num_secrets == 0)
    {
        fprintf(stderr, "%s\n", ERROR_NO_SECRETS);
        free(arca);
        return;
    }

    for (uint32_t i = 0; i < arca->num_secrets; i++)
    {
        if (arca->secrets[i].id == id)
        {
            printf("ID: %u | %s %s | %s %s | %s %s\n",
                   arca->secrets[i].id,
                   PROMPT_LABEL, arca->secrets[i].title,
                   PROMPT_LOGIN_OPTIONAL, arca->secrets[i].user,
                   PROMPT_SECRET, arca->secrets[i].secret);
            free(arca);
            return;
        }
    }

    fprintf(stderr, "%s\n", ERROR_ID_NOT_FOUND);
    free(arca);
}


static void print_usage(const char *prog_name)
{
    printf(USAGE, prog_name);
    printf("\n");
    printf(COMMANDS_LIST);
    printf("\n");

    
}


int main(int argc, char *argv[])
{
    #if defined(LANG_EN)
        setlocale(LC_ALL, "en_US.UTF-8");
    #elif defined(LANG_PT_BR)
        setlocale(LC_ALL, "pt_BR.UTF-8");
    #elif defined(LANG_RU)
        setlocale(LC_ALL, "ru_RU.UTF-8");
    #else
        if (!setlocale(LC_ALL, "")) {
            fprintf(stderr, "Failed to set locale. Using system default locale.\n");
        }
    #endif

    if (argc < 2)
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *command = NULL;
    const char *filename = DEFAULT_BINARY_FILE;

    int opt;
    int option_index = 0;
    
    
    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"password", required_argument, 0, 'p'},
        {"id", required_argument, 0, 'i'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    
    char *password_arg = NULL;
    uint32_t id_arg = 0;

    
    while ((opt = getopt_long(argc, argv, "f:p:i:h", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
        case 'f':
            filename = optarg;
            break;
        case 'p':
            password_arg = optarg;
            break;
        case 'i':
            id_arg = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    
    if (optind >= argc)
    { 
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    command = argv[optind];

    if (trng_init() != 0)
        HANDLE_ERROR(ERROR_FAILED_TO_INIT_ARCA);

    
    if (strcmp(command, COMMAND_INIT) == 0)
    {
        initialize_arca(filename);
    }
    else if (strcmp(command, COMMAND_ADD) == 0)
    {
        add_secret(filename);
    }
    else if (strcmp(command, COMMAND_VIEW) == 0)
    {
        view_secrets(filename);
    }
    else if (strcmp(command, COMMAND_REMOVE) == 0)
    {
        remove_secret(filename);
    }
    else if (strcmp(command, COMMAND_CHANGE_PASS) == 0)
    {
        change_password(filename);
    }
    else if (strcmp(command, COMMAND_GET) == 0)
    {
        
        if (password_arg == NULL || id_arg == 0)
        {
            fprintf(stderr, ERROR_GET_COMMAND_USAGE);
            print_usage(argv[0]);
            trng_cleanup();
            return EXIT_FAILURE;
        }
        get_secret(filename, password_arg, id_arg);
    }
    else
    {
        printf(UNKNOWN_COMMAND);
        trng_cleanup();
        return EXIT_FAILURE;
    }

    trng_cleanup();
    return EXIT_SUCCESS;
}