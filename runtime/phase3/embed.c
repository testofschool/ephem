#define _GNU_SOURCE
#include <sapi/embed/php_embed.h>
#include <Zend/zend_exceptions.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#ifdef ZTS
#error "The EPHEM warm PHP adapter requires the single-threaded NTS PHP build"
#endif

/* Only a single OS thread may call this adapter. Each request runs in a fork. */
static unsigned char *capture;
static size_t capture_len;
static const size_t capture_limit = 1048576;
static int overflow;
static char *script;
static char *request_code;
static int worker_state_fd = -1;
static char *embed_argv[] = { "ephem-php", NULL };

static void capture_flush(void *context) { (void)context; }

static int transfer(int fd, void *buffer, size_t size, int writing) {
    size_t offset = 0;
    while (offset < size) {
        ssize_t n = writing ? write(fd, (char *)buffer + offset, size - offset)
                            : read(fd, (char *)buffer + offset, size - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        offset += (size_t)n;
    }
    return 0;
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_ephem_exchange, 0, 1, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, command, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(ephem_state_exchange) {
    char *frame; size_t len;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(frame, len)
    ZEND_PARSE_PARAMETERS_END();
    if (worker_state_fd < 0 || len > 1048576) {
        zend_throw_exception(NULL, "state capability or command limit", 0); RETURN_THROWS();
    }
    uint32_t size = htonl((uint32_t)len);
    if (transfer(worker_state_fd, &size, 4, 1) || transfer(worker_state_fd, frame, len, 1)
        || transfer(worker_state_fd, &size, 4, 0)) {
        zend_throw_exception(NULL, "state channel disconnected", 0); RETURN_THROWS();
    }
    size = ntohl(size);
    if (size > 1048576) {
        zend_throw_exception(NULL, "state reply limit", 0); RETURN_THROWS();
    }
    zend_string *reply = zend_string_alloc(size, 0);
    if (transfer(worker_state_fd, ZSTR_VAL(reply), size, 0)) {
        zend_string_release(reply);
        zend_throw_exception(NULL, "incomplete state reply", 0); RETURN_THROWS();
    }
    ZSTR_VAL(reply)[size] = 0;
    RETURN_STR(reply);
}

static const zend_function_entry state_functions[] = {
    PHP_FE(ephem_state_exchange, arginfo_ephem_exchange)
    PHP_FE_END
};

static void defaults(HashTable *configuration) {
    const char *names[] = { "display_errors", "log_errors", "expose_php", "memory_limit" };
    const char *values[] = { "0", "0", "0", "-1" };
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        zval value;
        ZVAL_STRING(&value, values[i]);
        zend_hash_str_update(configuration, names[i], strlen(names[i]), &value);
    }
}

static size_t capture_write(const char *bytes, size_t len) {
    if (!capture) return len;
    if (len > capture_limit - capture_len) { overflow = 1; return 0; }
    memcpy(capture + capture_len, bytes, len);
    capture_len += len;
    return len;
}

/* Hex encoding prevents a request or filename from becoming executable source. */
static char *hex(const unsigned char *bytes, size_t len) {
    if (len > (SIZE_MAX - 1) / 2) return NULL;
    char *out = malloc(2 * len + 1);
    if (!out) return NULL;
    const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) { out[2*i] = digits[bytes[i] >> 4]; out[2*i+1] = digits[bytes[i] & 15]; }
    out[2*len] = 0;
    return out;
}

int ephem_php_boot(const char *bootstrap_path, const char *application_path) {
    if (script || !bootstrap_path || !application_path) return -1;
    script = hex((const unsigned char *)application_path, strlen(application_path));
    char *bootstrap = hex((const unsigned char *)bootstrap_path, strlen(bootstrap_path));
    if (!script || !bootstrap) { free(script); script = NULL; free(bootstrap); return -1; }
    php_embed_module.ub_write = capture_write;
    php_embed_module.flush = capture_flush;
    php_embed_module.php_ini_ignore = 1;
    php_embed_module.php_ini_ignore_cwd = 1;
    php_embed_module.ini_defaults = defaults;
    if (php_embed_init(1, embed_argv) == FAILURE) { free(bootstrap); return -1; }
    if (zend_register_functions(NULL, state_functions, NULL, MODULE_PERSISTENT) == FAILURE) {
        free(bootstrap); return -1;
    }
    char *code = NULL;
    if (asprintf(&code, "require hex2bin('%s');", bootstrap) < 0) { free(bootstrap); return -1; }
    free(bootstrap);
    int result = FAILURE;
    zend_first_try { result = zend_eval_string(code, NULL, "EPHEM bootstrap"); } zend_catch { result = FAILURE; } zend_end_try();
    free(code);
    if (result == FAILURE || EG(exception)) return -1;
    return 0;
}

int ephem_php_run(const unsigned char *input, size_t len, int state_fd,
                  const unsigned char **output, size_t *output_len) {
    if (!script || len > 65536 || !output || !output_len || state_fd < 0) return -1;
    capture = malloc(capture_limit);
    if (!capture) return -1;
    capture_len = 0; overflow = 0;
    worker_state_fd = state_fd;
    char *payload = hex(input, len);
    if (!payload) return -1;
    if (asprintf(&request_code,
        "EphemStateStream::$fd=%d; $_POST=json_decode(hex2bin('%s'),true,32,JSON_THROW_ON_ERROR);"
        "putenv('DB_DSN=ephem://state'); require hex2bin('%s');", state_fd, payload, script) < 0) {
        free(payload); return -1;
    }
    free(payload);
    int result = FAILURE;
    zend_first_try {
        result = zend_eval_string(request_code, NULL, "EPHEM request");
        if (EG(exception)) result = FAILURE;
    } zend_catch { result = FAILURE; } zend_end_try();
    free(request_code); request_code = NULL;
    zend_first_try { php_request_shutdown(NULL); } zend_catch { result = FAILURE; } zend_end_try();
    if (overflow || EG(exit_status) != 0) result = FAILURE;
    *output = capture; *output_len = capture_len;
    return result == SUCCESS ? 0 : -1;
}

/* Explicit laboratory probe, called only after real application mutations. */
int ephem_php_segfault(void) {
    void *page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return -1;
    *(volatile unsigned char *)page = 1;
    return -1;
}
