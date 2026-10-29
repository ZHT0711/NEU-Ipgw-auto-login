/* 这个脚本写于2026.8.28，若有失效大概是RSA公钥的问题，自己抓一下就好了
author : Skowosy(ZHT0711)*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>
#include <winhttp.h>
#include <wlanapi.h>
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

/* 释放内存结构 */
static void free_memory(struct MemoryStruct *chunk) {
    free(chunk->memory);
    chunk->memory = NULL;
    chunk->size = 0;
}

struct HttpResponse {
    struct MemoryStruct body;
    DWORD status_code;
    DWORD win_error;
    char location[2048];
};

static void init_http_response(struct HttpResponse *response) {
    init_memory(&response->body);
    response->status_code = 0;
    response->win_error = ERROR_SUCCESS;
    response->location[0] = '\0';
}

static void free_http_response(struct HttpResponse *response) {
    free_memory(&response->body);
}

static int utf8_to_wide(const char *input, wchar_t *output, int output_count) {
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1,
                               output, output_count) > 0;
}

static int query_location(HINTERNET request, char *output, size_t output_size) {
    wchar_t location[2048];
    DWORD location_bytes = sizeof(location);

    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION,
                             WINHTTP_HEADER_NAME_BY_INDEX, location,
                             &location_bytes, WINHTTP_NO_HEADER_INDEX)) {
        return 0;
    }

    return WideCharToMultiByte(CP_UTF8, 0, location, -1, output,
                               (int)output_size, NULL, NULL) > 0;
}

static int read_response_body(HINTERNET request, struct MemoryStruct *body) {
    const size_t max_response_size = 2 * 1024 * 1024;

    for (;;) {
        DWORD available = 0;
        DWORD bytes_read = 0;
        if (!WinHttpQueryDataAvailable(request, &available)) return 0;
        if (available == 0) return 1;
        if (body->size + available > max_response_size) return 0;

        char *new_memory = realloc(body->memory, body->size + available + 1);
        if (!new_memory) return 0;
        body->memory = new_memory;

        if (!WinHttpReadData(request, body->memory + body->size,
                             available, &bytes_read)) {
            return 0;
        }
        body->size += bytes_read;
        body->memory[body->size] = '\0';
    }
}

static int http_request(HINTERNET session, const wchar_t *method, const char *url,
                        const wchar_t *headers, const void *request_body,
                        DWORD request_size, int disable_redirects,
                        struct HttpResponse *response) {
    wchar_t wide_url[4096];
    wchar_t host[256];
    wchar_t path[3072];
    wchar_t extra[1024];
    wchar_t object_name[4096];
    URL_COMPONENTS parts;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    int success = 0;

    init_http_response(response);
    if (!response->body.memory || !utf8_to_wide(url, wide_url, ARRAYSIZE(wide_url))) {
        response->win_error = ERROR_INVALID_PARAMETER;
        return 0;
    }

    memset(&parts, 0, sizeof(parts));
    parts.dwStructSize = sizeof(parts);
    parts.lpszHostName = host;
    parts.dwHostNameLength = ARRAYSIZE(host) - 1;
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = ARRAYSIZE(path) - 1;
    parts.lpszExtraInfo = extra;
    parts.dwExtraInfoLength = ARRAYSIZE(extra) - 1;
    if (!WinHttpCrackUrl(wide_url, 0, 0, &parts)) {
        response->win_error = GetLastError();
        return 0;
    }
    host[parts.dwHostNameLength] = L'\0';
    path[parts.dwUrlPathLength] = L'\0';
    extra[parts.dwExtraInfoLength] = L'\0';
    if (swprintf(object_name, ARRAYSIZE(object_name), L"%ls%ls", path, extra) < 0) {
        response->win_error = ERROR_INSUFFICIENT_BUFFER;
        return 0;
    }

    connection = WinHttpConnect(session, host, parts.nPort, 0);
    if (!connection) goto cleanup;

    DWORD flags = parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    request = WinHttpOpenRequest(connection, method, object_name, NULL,
                                 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) goto cleanup;

    if (disable_redirects) {
        DWORD disabled_features = WINHTTP_DISABLE_REDIRECTS;
        if (!WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE,
                              &disabled_features, sizeof(disabled_features))) {
            goto cleanup;
        }
    }

    DWORD header_length = headers ? (DWORD)-1L : 0;
    if (!WinHttpSendRequest(request, headers, header_length,
                            (LPVOID)request_body, request_size, request_size, 0) ||
        !WinHttpReceiveResponse(request, NULL)) {
        goto cleanup;
    }

    DWORD status_size = sizeof(response->status_code);
    if (!WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &response->status_code,
                             &status_size, WINHTTP_NO_HEADER_INDEX)) {
        goto cleanup;
    }

    query_location(request, response->location, sizeof(response->location));
    if (!read_response_body(request, &response->body)) goto cleanup;
    success = 1;

cleanup:
    if (!success) response->win_error = GetLastError();
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    return success;
}

static char *url_encode(const char *input) {
    static const char hex[] = "0123456789ABCDEF";
    size_t input_len = strlen(input);
    char *output = malloc(input_len * 3 + 1);
    char *cursor = output;
    if (!output) return NULL;

    for (size_t i = 0; i < input_len; i++) {
        unsigned char ch = (unsigned char)input[i];
        if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
            *cursor++ = (char)ch;
        } else {
            *cursor++ = '%';
            *cursor++ = hex[ch >> 4];
            *cursor++ = hex[ch & 0x0F];
        }
    }
    *cursor = '\0';
    return output;
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
    HINTERNET session = WinHttpOpen(L"Mozilla/5.0 NEU-AutoLogin/1.0",
                                    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    struct HttpResponse response;
    int available = 0;

    if (!session) return 0;
    WinHttpSetTimeouts(session, 3000, 3000, 3000, 5000);
    if (http_request(session, L"HEAD", CONNECTIVITY_URL, NULL, NULL, 0, 0,
                     &response)) {
        available = response.status_code >= 200 && response.status_code < 400;
    }
    free_http_response(&response);
    WinHttpCloseHandle(session);
    return available;
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

/* 执行一次带有给定 acid 的登录尝试。会话由 WinHTTP 管理 Cookie。 */
static int login_with_acid(HINTERNET session, const char *student_id,
                           const char *password, int acid,
                           char *error_msg, size_t err_size) {
    char url[256];
    char rsa[512];
    char post_fields[1536];
    char sso_url[2048];
    char *lt = NULL;
    char *execution = NULL;
    char *rsa_encoded = NULL;
    char *lt_encoded = NULL;
    char *execution_encoded = NULL;
    struct HttpResponse page;
    struct HttpResponse response;
    int page_initialized = 0;
    int response_initialized = 0;
    int result = -1;

    snprintf(url, sizeof(url),
             "https://pass.neu.edu.cn/tpass/login?service=http://ipgw.neu.edu.cn/srun_portal_sso?ac_id=%d",
             acid);

    /* 1. 获取登录页，同时建立认证 Cookie。 */
    if (!http_request(session, L"GET", url, NULL, NULL, 0, 1, &page)) {
        page_initialized = 1;
        snprintf(error_msg, err_size, "访问pass.neu.edu.cn失败，WinHTTP错误: %lu",
                 (unsigned long)page.win_error);
        goto cleanup;
    }
    page_initialized = 1;
    if (page.status_code != 200) {
        snprintf(error_msg, err_size, "访问pass.neu.edu.cn失败，状态码: %lu",
                 (unsigned long)page.status_code);
        goto cleanup;
    }

    /* 2. 访问 checkacid 更新网关会话。 */
    if (!http_request(session, L"GET", "https://ipgw.neu.edu.cn/checkacid",
                      NULL, NULL, 0, 1, &response)) {
        response_initialized = 1;
        snprintf(error_msg, err_size, "访问checkacid失败，WinHTTP错误: %lu",
                 (unsigned long)response.win_error);
        goto cleanup;
    }
    response_initialized = 1;
    free_http_response(&response);
    response_initialized = 0;

    lt = extract_lt(page.body.memory);
    execution = extract_execution(page.body.memory);
    if (!lt || !execution) {
        snprintf(error_msg, err_size, "无法从登录页面提取lt或execution");
        goto cleanup;
    }

    if (encrypt_credentials(student_id, password, rsa, sizeof(rsa)) != 0) {
        snprintf(error_msg, err_size, "RSA加密账号密码失败");
        goto cleanup;
    }

    rsa_encoded = url_encode(rsa);
    lt_encoded = url_encode(lt);
    execution_encoded = url_encode(execution);
    if (!rsa_encoded || !lt_encoded || !execution_encoded) {
        snprintf(error_msg, err_size, "URL编码登录表单失败");
        goto cleanup;
    }

    int post_length = snprintf(
        post_fields, sizeof(post_fields),
        "rsa=%s&ul=%zu&pl=%zu&lt=%s&execution=%s&_eventId=submit",
        rsa_encoded, strlen(student_id), strlen(password), lt_encoded,
        execution_encoded);
    if (post_length < 0 || (size_t)post_length >= sizeof(post_fields)) {
        snprintf(error_msg, err_size, "登录表单过长");
        goto cleanup;
    }

    /* 3. 提交登录表单，保留 302 的 Location。 */
    if (!http_request(session, L"POST", url,
                      L"Content-Type: application/x-www-form-urlencoded\r\n",
                      post_fields, (DWORD)post_length, 1, &response)) {
        response_initialized = 1;
        snprintf(error_msg, err_size, "提交登录表单失败，WinHTTP错误: %lu",
                 (unsigned long)response.win_error);
        goto cleanup;
    }
    response_initialized = 1;
    if (response.status_code != 302) {
        snprintf(error_msg, err_size, "登录响应状态码不是302，而是: %lu",
                 (unsigned long)response.status_code);
        goto cleanup;
    }
    if (response.location[0] == '\0') {
        snprintf(error_msg, err_size, "未获取到重定向URL");
        goto cleanup;
    }

    const char *prefix = "http://ipgw.neu.edu.cn/";
    const char *v1 = "http://ipgw.neu.edu.cn/v1/";
    int sso_length;
    if (strncmp(response.location, prefix, strlen(prefix)) == 0) {
        sso_length = snprintf(sso_url, sizeof(sso_url), "%s%s", v1,
                              response.location + strlen(prefix));
    } else {
        sso_length = snprintf(sso_url, sizeof(sso_url), "%s", response.location);
    }
    if (sso_length < 0 || (size_t)sso_length >= sizeof(sso_url)) {
        snprintf(error_msg, err_size, "重定向URL过长");
        goto cleanup;
    }
    free_http_response(&response);
    response_initialized = 0;

    /* 4. 访问 SSO 链接完成登录。 */
    if (!http_request(session, L"GET", sso_url, NULL, NULL, 0, 0, &response)) {
        response_initialized = 1;
        snprintf(error_msg, err_size, "SSO登录请求失败，WinHTTP错误: %lu",
                 (unsigned long)response.win_error);
        goto cleanup;
    }
    response_initialized = 1;

    if (strstr(response.body.memory, "success") != NULL ||
        strstr(response.body.memory, "\"code\":0") != NULL ||
        strstr(response.body.memory, "ip_already_online_error") != NULL) {
        result = 0;
    } else {
        snprintf(error_msg, err_size, "SSO登录返回: %.440s", response.body.memory);
    }

cleanup:
    free(rsa_encoded);
    free(lt_encoded);
    free(execution_encoded);
    free(lt);
    free(execution);
    if (response_initialized) free_http_response(&response);
    if (page_initialized) free_http_response(&page);
    return result;
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

    printf("已连接校园网 %s，正在检查互联网连接...\n", ssid);
    if (internet_is_available()) {
        printf("网络已经连通，无需重复登录。\n");
        pause_if_interactive(scheduled);
        return 0;
    }

    if (read_config(student_id, sizeof(student_id), password, sizeof(password)) != 0) {
        printf("[错误] 无法读取配置文件 config.ini\n");
        pause_if_interactive(scheduled);
        return 1;
    }

    HINTERNET session = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) NEU-AutoLogin/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        printf("[错误] WinHTTP 初始化失败: %lu\n", (unsigned long)GetLastError());
        pause_if_interactive(scheduled);
        return 1;
    }
    WinHttpSetTimeouts(session, 5000, 5000, 10000, 10000);

    int acids[] = {15};  /* 三个目标 SSID 均为无线校园网 */
    int success = 0;

    for (size_t i = 0; i < sizeof(acids) / sizeof(acids[0]); i++) {
        printf("正在尝试使用 acid=%d 登录...\n", acids[i]);
        if (login_with_acid(session, student_id, password, acids[i],
                            error_msg, sizeof(error_msg)) == 0) {
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

    WinHttpCloseHandle(session);
    pause_if_interactive(scheduled);
    return success ? 0 : 1;
}
