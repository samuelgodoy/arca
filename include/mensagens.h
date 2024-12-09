#ifndef MENSAGENS_H
#define MENSAGENS_H

// Define o idioma padrão caso nenhum seja especificado
#if !defined(LANG_EN) && !defined(LANG_PT_BR) && !defined(LANG_RU)
    #define LANG_PT_BR
#endif

// Mensagens comuns a todos os idiomas
#define PROMPT_READ_LINE "%s"
#define ERROR_READ_INPUT "Erro ao ler a entrada."
#define SUCCESS_CANCELLED "Procedimento cancelado.\n"

// Definição das mensagens por idioma
#if defined(LANG_EN)

// Inglês
#define ERROR_FILE_NOT_FOUND "Error: The file '%s' does not exist. Please initialize the vault."
#define ERROR_LOAD_FAILED "Error: Failed to load the vault."
#define ERROR_SAVE_FAILED "Error: Failed to save the vault."
#define ERROR_ID_NOT_FOUND "ID not found."
#define ERROR_NO_SECRETS "No secrets found."
#define ERROR_NO_SECRETS_TO_REMOVE "No secrets to remove."
#define ERROR_FAILED_TO_INIT_ARCA "Failed to initialize the vault."
#define PROMPT_CONFIRM_ACTION "The file exists, do you want to overwrite? Enter 'y' or 'n'.\n"
#define PROMPT_MASTER_PASSWORD_CURRENT "Current master password: "
#define PROMPT_MASTER_PASSWORD_NEW "New master password: "
#define PROMPT_LABEL "Label: "
#define PROMPT_LOGIN_OPTIONAL "Login (Optional): "
#define PROMPT_SECRET "Secret: "
#define PROMPT_REMOVE_ID "Enter the ID to remove: "
#define PROMPT_GET_ID "Enter the ID to retrieve: "
#define ERROR_GET_COMMAND_USAGE "Error: The 'get' command requires the options -f <file>, -p <master_password>, and -i <ID>.\n"
#define SUCCESS_INIT_ARCA "Vault successfully initialized at %s.\n"
#define SUCCESS_CHANGE_PASSWORD "Password changed successfully.\n"
#define SUCCESS_ADD_SECRET "Secret added successfully.\n"
#define SUCCESS_REMOVE_SECRET "Secret removed.\n"
#define INVALID_RESPONSE "Invalid response. Please enter 'y' or 'n'.\n"
#define USAGE "Usage: %s <command> [options]\n"
#define UNKNOWN_COMMAND "Try another command.\n"
#define COMMAND_INIT "setup"
#define COMMAND_ADD "add"
#define COMMAND_VIEW "list"
#define COMMAND_REMOVE "delete"
#define COMMAND_CHANGE_PASS "password"
#define COMMAND_GET "get"
#define COMMAND_GET_DESC "Retrieve a secret by ID.\n" \
                          " Usage: get -f <file> -p <master_password> -i <ID>\n"
#define COMMANDS_LIST "ARCA - Confidential\n" \
                      "Available commands:\n" \
                      "  " COMMAND_INIT " \n" \
                      "    Setup the vault\n" \
                      "  " COMMAND_ADD " \n" \
                      "    Add a new secret\n" \
                      "  " COMMAND_VIEW " \n" \
                      "    List all secrets\n" \
                      "  " COMMAND_REMOVE " \n" \
                      "    Delete a secret\n" \
                      "  " COMMAND_CHANGE_PASS " \n" \
                      "    Change the master password\n" \
                      "  " COMMAND_GET " \n" \
                      "    " COMMAND_GET_DESC "\n"

#elif defined(LANG_PT_BR)

// Português do Brasil
#define ERROR_FILE_NOT_FOUND "Erro: O arquivo '%s' não existe. Inicialize o cofre."
#define ERROR_LOAD_FAILED "Erro: Falha ao carregar o cofre."
#define ERROR_SAVE_FAILED "Erro: Falha ao salvar o cofre."
#define ERROR_ID_NOT_FOUND "ID não encontrado."
#define ERROR_NO_SECRETS "Nenhum segredo encontrado."
#define ERROR_NO_SECRETS_TO_REMOVE "Nenhum segredo para remover."
#define ERROR_FAILED_TO_INIT_ARCA "Falha ao iniciar o cofre."
#define PROMPT_CONFIRM_ACTION "O arquivo existe, deseja substituir? Digite 's' ou 'n'.\n"
#define PROMPT_MASTER_PASSWORD_CURRENT "Senha mestre atual: "
#define PROMPT_MASTER_PASSWORD_NEW "Nova senha mestre: "
#define PROMPT_LABEL "Rótulo: "
#define PROMPT_LOGIN_OPTIONAL "Login (Opcional): "
#define PROMPT_SECRET "Segredo: "
#define PROMPT_REMOVE_ID "Digite o ID a remover: "
#define PROMPT_GET_ID "Digite o ID a resgatar: "
#define ERROR_GET_COMMAND_USAGE "Erro: O comando 'resgatar' requer as opções -f <arquivo>, -p <senha_mestre> e -i <ID>.\n"
#define SUCCESS_INIT_ARCA "Cofre inicializado com sucesso em %s.\n"
#define SUCCESS_CHANGE_PASSWORD "Senha alterada com sucesso.\n"
#define SUCCESS_ADD_SECRET "Segredo adicionado com sucesso.\n"
#define SUCCESS_REMOVE_SECRET "Segredo removido.\n"
#define INVALID_RESPONSE "Resposta incorreta. Digite 's' ou 'n'.\n"
#define USAGE "Uso: %s <comando> [opções]\n"
#define UNKNOWN_COMMAND "Tente outro comando.\n"
#define COMMAND_INIT "configurar"
#define COMMAND_ADD "inserir"
#define COMMAND_VIEW "listar"
#define COMMAND_REMOVE "excluir"
#define COMMAND_CHANGE_PASS "senha"
#define COMMAND_GET "resgatar"
#define COMMAND_GET_DESC "Resgatar um segredo pelo ID.\n" \
                          "Uso: resgatar -f <arquivo> -p <senha_mestre> -i <ID>\n"
#define COMMANDS_LIST "ARCA - Confidencial\n" \
                      "Comandos disponíveis:\n" \
                      "  " COMMAND_INIT " \n" \
                      "    Configurar o sistema\n" \
                      "  " COMMAND_ADD " \n" \
                      "    Inserir um novo segredo\n" \
                      "  " COMMAND_VIEW " \n" \
                      "    Listar todos os segredos\n" \
                      "  " COMMAND_REMOVE " \n" \
                      "    Excluir um segredo\n" \
                      "  " COMMAND_CHANGE_PASS " \n" \
                      "    Alterar a senha mestre\n" \
                      "  " COMMAND_GET " \n" \
                      "    " COMMAND_GET_DESC "\n"

#elif defined(LANG_RU)

// Russo
#define ERROR_FILE_NOT_FOUND "Ошибка: Файл '%s' не существует. Инициализируйте хранилище."
#define ERROR_LOAD_FAILED "Ошибка: Не удалось загрузить хранилище."
#define ERROR_SAVE_FAILED "Ошибка: Не удалось сохранить хранилище."
#define ERROR_ID_NOT_FOUND "ID не найден."
#define ERROR_NO_SECRETS "Секреты не найдены."
#define ERROR_NO_SECRETS_TO_REMOVE "Нет секретов для удаления."
#define ERROR_FAILED_TO_INIT_ARCA "Не удалось инициализировать хранилище."
#define PROMPT_CONFIRM_ACTION "Файл существует, хотите заменить? Введите 'д' или 'н'.\n"
#define PROMPT_MASTER_PASSWORD_CURRENT "Текущий главный пароль: "
#define PROMPT_MASTER_PASSWORD_NEW "Новый главный пароль: "
#define PROMPT_LABEL "Метка: "
#define PROMPT_LOGIN_OPTIONAL "Логин (Необязательно): "
#define PROMPT_SECRET "Секрет: "
#define PROMPT_REMOVE_ID "Введите ID для удаления: "
#define PROMPT_GET_ID "Введите ID для получения: "
#define ERROR_GET_COMMAND_USAGE "Ошибка: Команда 'получить' требует опций -f <файл>, -p <главный_пароль> и -i <ID>.\n"
#define SUCCESS_INIT_ARCA "Хранилище успешно инициализировано в %s.\n"
#define SUCCESS_CHANGE_PASSWORD "Пароль успешно изменен.\n"
#define SUCCESS_ADD_SECRET "Секрет успешно добавлен.\n"
#define SUCCESS_REMOVE_SECRET "Секрет удален.\n"
#define INVALID_RESPONSE "Некорректный ответ. Введите 'д' или 'н'.\n"
#define USAGE "Использование: %s <команда> [опции]\n"
#define UNKNOWN_COMMAND "Попробуйте другую команду.\n"
#define COMMAND_INIT "настроить"
#define COMMAND_ADD "внести"
#define COMMAND_VIEW "отобразить"
#define COMMAND_REMOVE "удалить"
#define COMMAND_CHANGE_PASS "пароль"
#define COMMAND_GET "получить"
#define COMMAND_GET_DESC "Получить секрет по ID. \n" \
                          "Использование: получить -f <файл> -p <главный_пароль> -i <ID>\n"
#define COMMANDS_LIST "АРКА - Конфиденциально\n" \
                      "Доступные команды:\n" \
                      "  " COMMAND_INIT " \n" \
                      "    Настроить хранилище\n" \
                      "  " COMMAND_ADD " \n" \
                      "    Внести новый секрет\n" \
                      "  " COMMAND_VIEW " \n" \
                      "    Отобразить все секреты\n" \
                      "  " COMMAND_REMOVE " \n" \
                      "    Удалить секрет\n" \
                      "  " COMMAND_CHANGE_PASS " \n" \
                      "    Изменить главный пароль\n" \
                      "  " COMMAND_GET " \n" \
                      "    " COMMAND_GET_DESC "\n"

#endif // Idioma definido

#endif // MENSAGENS_H
