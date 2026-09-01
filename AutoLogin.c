/* 这个脚本写于2026.8.28，若有失效大概是RSA公钥的问题，自己抓一下就好了
author : Skowosy(ZHT0711)*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wlanapi.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

/* 配置文件信息 */
#define CONFIG_FILE "config.ini"
#define MAX_LINE_LEN 256
#define CONNECTIVITY_URL "https://www.baidu.com/"

/* 登录页 login_neu.js（v=20260302）使用的 RSA 公钥 */
#define LOGIN_PUBLIC_KEY \
    "-----BEGIN PUBLIC KEY-----\n" \
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnjA28DLKXZzxbKmo9/1WkVLf1mr+wtLXLXt6sC4WiBCtsbzF5ewm7ARZeAdS3iZtqlYPn6IcUoOw42H8nAK/tfFcIb6dZ1K0atn0U39oWCGPzYuKtLJeMuNZiDXVuAXtojrckOjLW9B3gUnaNGLuIx0fYe66l0o9WjU2cGLNZQfiIxs2h00z1EA9IdSnVxiVQWSD+lsP3JZXh2TT287la4Y4603SQNKTK/QvXfcmccwTEd1IW6HwGxD6QrkInBiHisKWxmveN7UDSaQRZ/J97G0YC32pD38WT53izXeK0p/kU/X37VP555um1wVWFvPIuc9I7gMP1+hq5a+X6c++tQIDAQAB\n" \
    "-----END PUBLIC KEY-----\n"

/* 存储响应数据的内存结构 */
struct MemoryStruct {
    char *memory;
    size_t size;
};

/* 初始化内存结构 */
static void init_memory(struct MemoryStruct *chunk) {
    chunk->memory = malloc(1);
    chunk->size = 0;
    if (chunk->memory) chunk->memory[0] = '\0';
}

/* libcurl写回调函数 */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        printf("内存不足!\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

/* 释放内存结构 */
static void free_memory(struct MemoryStruct *chunk) {
    free(chunk->memory);
    chunk->memory = NULL;
    chunk->size = 0;
}

static int is_target_ssid(const DOT11_SSID *ssid) {
    static const char *target_ssids[] = {"NEU", "NEU-2.4G", "NEU-mobile"};

    for (size_t i = 0; i < sizeof(target_ssids) / sizeof(target_ssids[0]); i++) {
        size_t target_len = strlen(target_ssids[i]);
        if (ssid->uSSIDLength == target_len &&
            memcmp(ssid->ucSSID, target_ssids[i], target_len) == 0) {
            return 1;
        }
    }
    return 0;
}

/* 返回 1 表示连接到目标校园网，0 表示不是，-1 表示 WLAN API 调用失败。 */
static int get_target_ssid(char *ssid_text, size_t text_size) {
    HANDLE client = NULL;
    PWLAN_INTERFACE_INFO_LIST interfaces = NULL;
    DWORD negotiated_version = 0;
    DWORD result = WlanOpenHandle(2, NULL, &negotiated_version, &client);
    int matched = 0;

    if (result != ERROR_SUCCESS) return -1;
    result = WlanEnumInterfaces(client, NULL, &interfaces);
    if (result != ERROR_SUCCESS) {
        WlanCloseHandle(client, NULL);
        return -1;
    }

    for (DWORD i = 0; i < interfaces->dwNumberOfItems; i++) {
        WLAN_INTERFACE_INFO *interface_info = &interfaces->InterfaceInfo[i];
        PWLAN_CONNECTION_ATTRIBUTES connection = NULL;
        DWORD connection_size = 0;
        WLAN_OPCODE_VALUE_TYPE opcode_type;

        if (interface_info->isState != wlan_interface_state_connected) continue;
        result = WlanQueryInterface(client, &interface_info->InterfaceGuid,
                                    wlan_intf_opcode_current_connection, NULL,
                                    &connection_size, (PVOID *)&connection, &opcode_type);
        if (result != ERROR_SUCCESS || !connection) continue;

        const DOT11_SSID *ssid = &connection->wlanAssociationAttributes.dot11Ssid;
        if (is_target_ssid(ssid)) {
            size_t copy_len = ssid->uSSIDLength;
            if (copy_len >= text_size) copy_len = text_size - 1;
            memcpy(ssid_text, ssid->ucSSID, copy_len);
            ssid_text[copy_len] = '\0';
            matched = 1;
            WlanFreeMemory(connection);
            break;
        }
        WlanFreeMemory(connection);
    }

    WlanFreeMemory(interfaces);
    WlanCloseHandle(client, NULL);
    return matched;
}

/* 只发一个短超时的 HTTPS HEAD 请求，避免已经联网时重复认证。 */
static int internet_is_available(void) {
    CURL *curl = curl_easy_init();
    CURLcode result;
    long status_code = 0;

    if (!curl) return 0;
    curl_easy_setopt(curl, CURLOPT_URL, CONNECTIVITY_URL);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 3000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 NEU-AutoLogin/1.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    result = curl_easy_perform(curl);
    if (result == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    }
    curl_easy_cleanup(curl);
    return result == CURLE_OK && status_code >= 200 && status_code < 400;
}

static void pause_if_interactive(int scheduled) {
    if (!scheduled) system("pause");
}

/* 按网页端 JSEncrypt 的方式，用 RSA/PKCS#1 v1.5 加密“学号+密码”并输出 Base64 */
static int encrypt_credentials(const char *student_id, const char *password,
                               char *output, size_t output_size) {
    int result = -1;
    char plain[256];
    BIO *bio = NULL;
    EVP_PKEY *public_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *encrypted = NULL;
    size_t encrypted_size = 0;

    int written = snprintf(plain, sizeof(plain), "%s%s", student_id, password);
    if (written < 0 || (size_t)written >= sizeof(plain)) goto cleanup;

    bio = BIO_new_mem_buf(LOGIN_PUBLIC_KEY, -1);
    if (!bio) goto cleanup;
    public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!public_key) goto cleanup;

    ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) goto cleanup;
    if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_size,
                         (const unsigned char *)plain, strlen(plain)) <= 0) goto cleanup;

    encrypted = malloc(encrypted_size);
    if (!encrypted) goto cleanup;
    if (EVP_PKEY_encrypt(ctx, encrypted, &encrypted_size,
                         (const unsigned char *)plain, strlen(plain)) <= 0) goto cleanup;

    size_t base64_size = 4 * ((encrypted_size + 2) / 3) + 1;
    if (base64_size > output_size) goto cleanup;
    EVP_EncodeBlock((unsigned char *)output, encrypted, (int)encrypted_size);
    result = 0;

cleanup:
    free(encrypted);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    BIO_free(bio);
    return result;
}

/* 从HTML中提取指定name的input value */
static char *extract_input_value(const char *html, const char *name) {
    if (!html || !name) return NULL;

    char search_pattern[128];
    snprintf(search_pattern, sizeof(search_pattern), "name=\"%s\" value=\"", name);

    char *pos = strstr(html, search_pattern);
    if (!pos) return NULL;

    pos += strlen(search_pattern);
    char *end = strchr(pos, '"');
    if (!end) return NULL;

    size_t len = end - pos;
    char *value = malloc(len + 1);
    if (!value) return NULL;
    strncpy(value, pos, len);
    value[len] = '\0';
    return value;
}

/* 从HTML中提取lt（login token） */
static char *extract_lt(const char *html) {
    char *pos = strstr(html, "id=\"lt\" name=\"lt\" value=\"");
    if (!pos) {
        pos = strstr(html, "name=\"lt\" value=\"");
        if (!pos) return NULL;
        pos += strlen("name=\"lt\" value=\"");
    } else {
        pos += strlen("id=\"lt\" name=\"lt\" value=\"");
    }

    char *end = strchr(pos, '"');
    if (!end) return NULL;

    size_t len = end - pos;
    char *lt = malloc(len + 1);
    if (!lt) return NULL;
    strncpy(lt, pos, len);
    lt[len] = '\0';
    return lt;
}

/* 从HTML中提取execution */
static char *extract_execution(const char *html) {
    return extract_input_value(html, "execution");
}

/* 获取 exe 所在目录，并拼接配置文件名 */
static int get_config_path(char *out_path, size_t out_size) {
    DWORD path_len = GetModuleFileNameA(NULL, out_path, (DWORD)out_size);
    if (path_len == 0 || path_len >= out_size) return -1;

    char *last_slash = strrchr(out_path, '\\');
    if (!last_slash) return -1;

    size_t directory_len = (size_t)(last_slash - out_path) + 1;
    size_t config_len = strlen(CONFIG_FILE);
    if (directory_len + config_len + 1 > out_size) return -1;
    memcpy(out_path + directory_len, CONFIG_FILE, config_len + 1);
    return 0;
}

/* 读取配置文件，获取学号和密码 */
static int read_config(char *student_id, size_t id_size, char *password, size_t pw_size) {
    char config_path[MAX_PATH];
    if (get_config_path(config_path, sizeof(config_path)) != 0) {
        fprintf(stderr, "无法确定配置文件路径\n");
        return -1;
    }

    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        fprintf(stderr, "无法打开配置文件 %s\n", config_path);
        return -1;
    }

    char line[MAX_LINE_LEN];
    int found_id = 0, found_pw = 0;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;

        if (line[0] == '\0' || line[0] == ';' || line[0] == '#')
            continue;

        char *delimiter = strpbrk(line, "=:");
        if (!delimiter) continue;

        *delimiter = '\0';
        char *key = line;
        char *value = delimiter + 1;

        while (*key == ' ' || *key == '\t') key++;
        char *key_end = key + strlen(key) - 1;
        while (key_end >= key && (*key_end == ' ' || *key_end == '\t')) {
            *key_end = '\0';
            key_end--;
        }

        while (*value == ' ' || *value == '\t') value++;
        char *value_end = value + strlen(value) - 1;
        while (value_end >= value && (*value_end == ' ' || *value_end == '\t')) {
            *value_end = '\0';
            value_end--;
        }

        if (strcasecmp(key, "StudentID") == 0 || strcasecmp(key, "studentid") == 0) {
            strncpy(student_id, value, id_size - 1);
            student_id[id_size - 1] = '\0';
            found_id = 1;
        } else if (strcasecmp(key, "password") == 0) {
            strncpy(password, value, pw_size - 1);
            password[pw_size - 1] = '\0';
            found_pw = 1;
        }
    }
    fclose(fp);

    if (!found_id || !found_pw) {
        fprintf(stderr, "配置文件中缺少 StudentID 或 password\n");
        return -1;
    }
    return 0;
}

/* 执行一次带有给定acid的登录尝试 */
static int login_with_acid(CURL *curl, const char *student_id, const char *password,
                           int acid, char *error_msg, size_t err_size) {
    CURLcode res;
    char url[256];
    struct MemoryStruct page;
    char *lt = NULL, *execution = NULL;
    long status_code = 0;

    snprintf(url, sizeof(url),
             "https://pass.neu.edu.cn/tpass/login?service=http://ipgw.neu.edu.cn/srun_portal_sso?ac_id=%d",
             acid);

    init_memory(&page);

    /* 设置通用选项 */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&page);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
                     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                     "AppleWebKit/537.36 Chrome/120 Safari/537.36");
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    /* 1. 获取登录页面 */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        snprintf(error_msg, err_size, "访问pass.neu.edu.cn失败: %s", curl_easy_strerror(res));
        free_memory(&page);
        return -1;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    if (status_code != 200) {
        snprintf(error_msg, err_size, "访问pass.neu.edu.cn失败，状态码: %ld", status_code);
        free_memory(&page);
        return -1;
    }

    /* 2. 访问 checkacid 更新会话 */
    {
        struct MemoryStruct check_page;
        init_memory(&check_page);
        curl_easy_setopt(curl, CURLOPT_URL, "https://ipgw.neu.edu.cn/checkacid");
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&check_page);
        res = curl_easy_perform(curl);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&page);
        if (res != CURLE_OK) {
            snprintf(error_msg, err_size, "访问checkacid失败: %s", curl_easy_strerror(res));
            free_memory(&check_page);
            free_memory(&page);
            return -1;
        }
        free_memory(&check_page);
    }

    /* 提取 lt 和 execution */
    lt = extract_lt(page.memory);
    execution = extract_execution(page.memory);
    if (!lt || !execution) {
        snprintf(error_msg, err_size, "无法从登录页面提取lt或execution");
        if (lt) free(lt);
        if (execution) free(execution);
        free_memory(&page);
        return -1;
    }

    /* 构造 POST 数据：新版登录页要求 RSA 加密，并对表单值进行 URL 编码 */
    char rsa[512];
    if (encrypt_credentials(student_id, password, rsa, sizeof(rsa)) != 0) {
        snprintf(error_msg, err_size, "RSA加密账号密码失败");
        free(lt);
        free(execution);
        free_memory(&page);
        return -1;
    }
    int ul = strlen(student_id);
    int pl = strlen(password);

    char *rsa_encoded = curl_easy_escape(curl, rsa, 0);
    char *lt_encoded = curl_easy_escape(curl, lt, 0);
    char *execution_encoded = curl_easy_escape(curl, execution, 0);
    if (!rsa_encoded || !lt_encoded || !execution_encoded) {
        snprintf(error_msg, err_size, "URL编码登录表单失败");
        curl_free(rsa_encoded);
        curl_free(lt_encoded);
        curl_free(execution_encoded);
        free(lt);
        free(execution);
        free_memory(&page);
        return -1;
    }

    char post_fields[1536];
    snprintf(post_fields, sizeof(post_fields),
             "rsa=%s&ul=%d&pl=%d&lt=%s&execution=%s&_eventId=submit",
             rsa_encoded, ul, pl, lt_encoded, execution_encoded);
    curl_free(rsa_encoded);
    curl_free(lt_encoded);
    curl_free(execution_encoded);

    /* 3. 提交登录表单 */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post_fields));

    free_memory(&page);
    init_memory(&page);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        snprintf(error_msg, err_size, "提交登录表单失败: %s", curl_easy_strerror(res));
        free(lt);
        free(execution);
        free_memory(&page);
        return -1;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    if (status_code != 302) {
        snprintf(error_msg, err_size, "登录响应状态码不是302，而是: %ld", status_code);
        free(lt);
        free(execution);
        free_memory(&page);
        return -1;
    }

    /* 获取重定向URL */
    char *location = NULL;
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &location);
    if (!location) {
        snprintf(error_msg, err_size, "未获取到重定向URL");
        free(lt);
        free(execution);
        free_memory(&page);
        return -1;
    }

    /* 构造SSO链接 */
    char sso_url[512];
    const char *prefix = "http://ipgw.neu.edu.cn/";
    const char *v1 = "http://ipgw.neu.edu.cn/v1/";
    if (strncmp(location, prefix, strlen(prefix)) == 0) {
        snprintf(sso_url, sizeof(sso_url), "%s%s", v1, location + strlen(prefix));
    } else {
        strncpy(sso_url, location, sizeof(sso_url) - 1);
        sso_url[sizeof(sso_url) - 1] = '\0';
    }

    /* 4. 访问SSO链接完成登录 */
    curl_easy_setopt(curl, CURLOPT_URL, sso_url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    free_memory(&page);
    init_memory(&page);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        snprintf(error_msg, err_size, "SSO登录请求失败: %s", curl_easy_strerror(res));
        free(lt);
        free(execution);
        free_memory(&page);
        return -1;
    }

    /* 正常登录成功，或当前 IP 已在线，都视为成功 */
    if (strstr(page.memory, "success") != NULL ||
        strstr(page.memory, "\"code\":0") != NULL ||
        strstr(page.memory, "ip_already_online_error") != NULL) {
        free(lt);
        free(execution);
        free_memory(&page);
        return 0;  /* 成功 */
    } else {
        snprintf(error_msg, err_size, "SSO登录返回: %s", page.memory);
        free(lt);
        free(execution);
        free_memory(&page);
        return -1;
    }
}

int main(int argc, char **argv) {
    int scheduled = argc > 1 && strcmp(argv[1], "--scheduled") == 0;

    if (scheduled) {
        HWND console = GetConsoleWindow();
        if (console) ShowWindow(console, SW_HIDE);
    }

    /* 解决中文乱码 */
    SetConsoleOutputCP(65001);

    char student_id[64];
    char password[128];
    char error_msg[512];
    char ssid[DOT11_SSID_MAX_LENGTH + 1] = {0};

    int ssid_result = get_target_ssid(ssid, sizeof(ssid));
    if (ssid_result <= 0) {
        if (!scheduled) {
            printf(ssid_result == 0
                       ? "当前未连接到 NEU、NEU-2.4G 或 NEU-mobile，无需登录。\n"
                       : "无法读取当前 Wi-Fi，已跳过自动登录。\n");
        }
        pause_if_interactive(scheduled);
        return ssid_result < 0 ? 2 : 0;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        printf("[错误] libcurl 全局初始化失败\n");
        pause_if_interactive(scheduled);
        return 1;
    }

    printf("已连接校园网 %s，正在检查互联网连接...\n", ssid);
    if (internet_is_available()) {
        printf("网络已经连通，无需重复登录。\n");
        curl_global_cleanup();
        pause_if_interactive(scheduled);
        return 0;
    }

    if (read_config(student_id, sizeof(student_id), password, sizeof(password)) != 0) {
        printf("[错误] 无法读取配置文件 config.ini\n");
        curl_global_cleanup();
        pause_if_interactive(scheduled);
        return 1;
    }

    /* 初始化 libcurl */
    CURL *curl = curl_easy_init();
    if (!curl) {
        printf("[错误] libcurl 初始化失败\n");
        curl_global_cleanup();
        pause_if_interactive(scheduled);
        return 1;
    }

    int acids[] = {15};  /* 三个目标 SSID 均为无线校园网 */
    int success = 0;

    for (size_t i = 0; i < sizeof(acids) / sizeof(acids[0]); i++) {
        printf("正在尝试使用 acid=%d 登录...\n", acids[i]);
        if (login_with_acid(curl, student_id, password, acids[i], error_msg, sizeof(error_msg)) == 0) {
            printf("[成功] 登录成功！(acid=%d)\n", acids[i]);
            success = 1;
            break;
        } else {
            printf("[失败] acid=%d 登录失败，原因：%s\n", acids[i], error_msg);
        }
    }

    if (!success) {
        printf("[结果] 所有登录尝试均失败，请检查账号密码或网络。\n");
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    pause_if_interactive(scheduled);
    return success ? 0 : 1;
}
