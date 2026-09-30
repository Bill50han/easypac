#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <idn2.h>
#include <libpsl.h>
#include <openssl/sha.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <yaml.h>

typedef struct {
    const char *name, *via;
    yaml_node_t *domains;
} Group;

typedef struct {
    char *domain;
    const char *base, *via;
    int keep;
} Rule;

static yaml_document_t document;
static const psl_ctx_t *psl;
static Group *groups;
static Rule *rules;
static char **routes;
static size_t ngroups, nrules, nroutes;
static const char *fallback;
static int cgi;

static void fail(yaml_node_t *node, const char *format, ...)
{
    va_list args;
    fprintf(stderr, "easypac: ");
    if (node)
        fprintf(stderr, "line %zu: ", node->start_mark.line + 1);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fputc('\n', stderr);
    if (cgi) {
        printf("Status: 500 Internal Server Error\r\n"
               "Content-Type: text/plain; charset=utf-8\r\n"
               "Cache-Control: no-store\r\n\r\n");
        if (strcmp(getenv("REQUEST_METHOD"), "HEAD"))
            puts("Cannot generate PAC. Check the server error log.");
    }
    exit(EXIT_FAILURE);
}

static void *resize(void *ptr, size_t count, size_t size)
{
    if (count > (size_t)-1 / size)
        fail(NULL, "configuration is too large");
    void *result = realloc(ptr, count * size);
    if (!result)
        fail(NULL, "out of memory");
    return result;
}

static yaml_node_t *node_at(int id)
{
    return yaml_document_get_node(&document, id);
}

static const char *scalar(yaml_node_t *node)
{
    if (!node || node->type != YAML_SCALAR_NODE)
        fail(node, "expected a scalar string");
    const char *text = (const char *)node->data.scalar.value;
    if (strlen(text) != node->data.scalar.length)
        fail(node, "NUL bytes are not allowed");
    return text;
}

static void sequence(yaml_node_t *node)
{
    if (!node || node->type != YAML_SEQUENCE_NODE)
        fail(node, "expected a YAML list");
}

static void mapping(yaml_node_t *node)
{
    if (!node || node->type != YAML_MAPPING_NODE)
        fail(node, "expected a YAML mapping");
    for (yaml_node_pair_t *p = node->data.mapping.pairs.start;
         p < node->data.mapping.pairs.top; p++) {
        const char *key = scalar(node_at(p->key));
        for (yaml_node_pair_t *q = node->data.mapping.pairs.start; q < p; q++)
            if (!strcmp(key, scalar(node_at(q->key))))
                fail(node_at(p->key), "duplicate key '%s'", key);
    }
}

static yaml_node_t *field(yaml_node_t *map, const char *name)
{
    for (yaml_node_pair_t *p = map->data.mapping.pairs.start;
         p < map->data.mapping.pairs.top; p++)
        if (!strcmp(scalar(node_at(p->key)), name))
            return node_at(p->value);
    return NULL;
}

static char *hostname(yaml_node_t *node)
{
    uint8_t *ascii = NULL;
    const char *input = scalar(node);
    int rc = idn2_lookup_u8((const uint8_t *)input, &ascii,
                          IDN2_NONTRANSITIONAL | IDN2_USE_STD3_ASCII_RULES);
    if (rc != IDN2_OK)
        fail(node, "invalid hostname '%s': %s", input, idn2_strerror(rc));
    size_t len = strlen((char *)ascii);
    if (len && ascii[len - 1] == '.')
        ascii[--len] = 0;
    if (!len || len > 253)
        fail(node, "invalid hostname '%s'", input);
    size_t label = 0;
    for (size_t i = 0; i <= len; i++) {
        unsigned char ch = ascii[i];
        if (ch == '.' || !ch) {
            if (!label || label > 63 || ascii[i - 1] == '-')
                fail(node, "invalid hostname '%s'", input);
            label = 0;
        } else {
            if (!(isalnum(ch) || ch == '-') || (!label && ch == '-'))
                fail(node, "invalid hostname '%s'", input);
            ascii[i] = (uint8_t)tolower(ch);
            label++;
        }
    }
    char *result = strdup((char *)ascii);
    idn2_free(ascii);
    if (!result)
        fail(NULL, "out of memory");
    return result;
}

static const char *intern(const char *via)
{
    for (size_t i = 0; i < nroutes; i++)
        if (!strcmp(routes[i], via))
            return routes[i];
    routes = resize(routes, nroutes + 1, sizeof(*routes));
    routes[nroutes] = strdup(via);
    if (!routes[nroutes])
        fail(NULL, "out of memory");
    return routes[nroutes++];
}

static const char *parse_route(yaml_node_t *map, int with_domains)
{
    mapping(map);
    for (yaml_node_pair_t *p = map->data.mapping.pairs.start;
         p < map->data.mapping.pairs.top; p++) {
        const char *key = scalar(node_at(p->key));
        if (strcmp(key, "method") && strcmp(key, "url") && strcmp(key, "port") &&
            !(with_domains && !strcmp(key, "domains")))
            fail(node_at(p->key), "unknown route field '%s'", key);
    }
    const char *method = scalar(field(map, "method")), *kind = NULL;
    if (!strcasecmp(method, "direct")) {
        if (field(map, "url") || field(map, "port"))
            fail(map, "direct needs only method (and domains in proxy)");
        return intern("DIRECT");
    }
    if (!strcasecmp(method, "http")) kind = "PROXY";
    else if (!strcasecmp(method, "https")) kind = "HTTPS";
    else if (!strcasecmp(method, "socks")) kind = "SOCKS";
    else if (!strcasecmp(method, "socks4")) kind = "SOCKS4";
    else if (!strcasecmp(method, "socks5")) kind = "SOCKS5";
    else fail(map, "unknown method '%s'", method);

    yaml_node_t *url_node = field(map, "url"), *port_node = field(map, "port");
    const char *url = scalar(url_node), *port_text = scalar(port_node);
    unsigned port = 0;
    if (!*port_text)
        fail(port_node, "port must be an integer from 1 to 65535");
    for (const char *p = port_text; *p; p++) {
        if (*p < '0' || *p > '9' || port > 6553)
            fail(port_node, "port must be an integer from 1 to 65535");
        port = port * 10 + (unsigned)(*p - '0');
    }
    if (!port || port > 65535)
        fail(port_node, "port must be an integer from 1 to 65535");

    char ipv6[INET6_ADDRSTRLEN], address[INET6_ADDRSTRLEN + 2];
    struct in6_addr binary;
    size_t len = strlen(url);
    const char *candidate = url;
    if (len > 2 && url[0] == '[' && url[len - 1] == ']' && len - 2 < sizeof(ipv6)) {
        memcpy(ipv6, url + 1, len - 2);
        ipv6[len - 2] = 0;
        candidate = ipv6;
    }
    char *dns = NULL;
    if (inet_pton(AF_INET6, candidate, &binary) == 1) {
        if (!inet_ntop(AF_INET6, &binary, ipv6, sizeof(ipv6)))
            fail(url_node, "invalid IPv6 proxy address");
        snprintf(address, sizeof(address), "[%s]", ipv6);
        url = address;
    } else {
        dns = hostname(url_node);
        url = dns;
    }
    char action[320];
    snprintf(action, sizeof(action), "%s %s:%u", kind, url, port);
    free(dns);
    return intern(action);
}

static void load(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file)
        fail(NULL, "cannot open '%s': %s", path, strerror(errno));
    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser))
        fail(NULL, "cannot initialize YAML parser");
    yaml_parser_set_input_file(&parser, file);
    if (!yaml_parser_load(&parser, &document))
        fail(NULL, "YAML line %zu: %s", parser.problem_mark.line + 1, parser.problem);
    yaml_document_t extra;
    if (!yaml_parser_load(&parser, &extra))
        fail(NULL, "YAML line %zu: %s", parser.problem_mark.line + 1, parser.problem);
    if (yaml_document_get_root_node(&extra))
        fail(NULL, "expected one YAML document");
    yaml_document_delete(&extra);
    yaml_parser_delete(&parser);
    fclose(file);

    psl = psl_builtin();
    if (!psl)
        fail(NULL, "no PSL data available");
    yaml_node_t *root = yaml_document_get_root_node(&document);
    mapping(root);
    for (yaml_node_pair_t *p = root->data.mapping.pairs.start;
         p < root->data.mapping.pairs.top; p++) {
        const char *name = scalar(node_at(p->key));
        if (!strcmp(name, "proxy") || !strcmp(name, "default"))
            continue;
        yaml_node_t *domains = node_at(p->value);
        sequence(domains);
        groups = resize(groups, ngroups + 1, sizeof(*groups));
        groups[ngroups++] = (Group){name, NULL, domains};
    }
    fallback = parse_route(field(root, "default"), 0);
    yaml_node_t *proxy = field(root, "proxy");
    sequence(proxy);
    for (yaml_node_item_t *p = proxy->data.sequence.items.start;
         p < proxy->data.sequence.items.top; p++) {
        yaml_node_t *entry = node_at(*p);
        const char *via = parse_route(entry, 1);
        yaml_node_t *refs = field(entry, "domains");
        sequence(refs);
        for (yaml_node_item_t *q = refs->data.sequence.items.start;
             q < refs->data.sequence.items.top; q++) {
            const char *name = scalar(node_at(*q));
            size_t i;
            for (i = 0; i < ngroups && strcmp(groups[i].name, name); i++);
            if (i == ngroups)
                fail(node_at(*q), "unknown domain group '%s'", name);
            if (groups[i].via && strcmp(groups[i].via, via))
                fail(node_at(*q), "group '%s' has conflicting routes", name);
            groups[i].via = via;
        }
    }
    for (size_t i = 0; i < ngroups; i++) {
        yaml_node_t *list = groups[i].domains;
        for (yaml_node_item_t *p = list->data.sequence.items.start;
             p < list->data.sequence.items.top; p++) {
            char *domain = hostname(node_at(*p));
            const char *base = psl_registrable_domain(psl, domain);
            if (!base)
                fail(node_at(*p), "'%s' is a public suffix, not a registrable domain", domain);
            if (!groups[i].via) {
                free(domain);
                continue;
            }
            rules = resize(rules, nrules + 1, sizeof(*rules));
            rules[nrules++] = (Rule){domain, base, groups[i].via, 1};
        }
    }
}

static int compare_rules(const void *a, const void *b)
{
    const Rule *x = a, *y = b;
    return strcmp(x->domain, y->domain);
}

static int compare_groups(const void *a, const void *b)
{
    const Rule *x = a, *y = b;
    int result = strcmp(x->base, y->base);
    return result ? result : strcmp(x->domain, y->domain);
}

static int compare_routes(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static size_t optimize(void)
{
    if (nrules)
        qsort(rules, nrules, sizeof(*rules), compare_rules);
    qsort(routes, nroutes, sizeof(*routes), compare_routes);
    size_t unique = 0;
    for (size_t i = 0; i < nrules; i++) {
        if (unique && !strcmp(rules[unique - 1].domain, rules[i].domain)) {
            if (strcmp(rules[unique - 1].via, rules[i].via))
                fail(NULL, "domain '%s' has conflicting routes", rules[i].domain);
            free(rules[i].domain);
        } else {
            rules[unique++] = rules[i];
        }
    }
    nrules = unique;
    size_t kept = 0;
    /* Compare to the nearest ancestor, including ancestors later omitted. */
    for (size_t i = 0; i < nrules; i++) {
        const char *inherited = fallback;
        const char *parent = strchr(rules[i].domain, '.');
        while (parent) {
            Rule key = {(char *)(parent + 1), rules[i].base, NULL, 0};
            Rule *found = bsearch(&key, rules, nrules, sizeof(*rules), compare_rules);
            if (found) {
                inherited = found->via;
                break;
            }
            parent = strchr(parent + 1, '.');
        }
        rules[i].keep = strcmp(rules[i].via, inherited) != 0;
        kept += (size_t)rules[i].keep;
    }
    if (nrules)
        qsort(rules, nrules, sizeof(*rules), compare_groups);
    size_t used = 0;
    for (size_t i = 0; i < nroutes; i++) {
        int needed = routes[i] == fallback;
        for (size_t j = 0; j < nrules && !needed; j++)
            needed = rules[j].keep && rules[j].via == routes[i];
        if (needed) routes[used++] = routes[i];
        else free(routes[i]);
    }
    nroutes = used;
    return kept;
}

static size_t route_index(const char *via)
{
    char **found = bsearch(&via, routes, nroutes, sizeof(*routes), compare_routes);
    return (size_t)(found - routes);
}

static char *generate(size_t *length)
{
    char *body = NULL;
    FILE *out = open_memstream(&body, length);
    if (!out)
        fail(NULL, "cannot allocate PAC buffer");
    fputs("// Generated by easypac; grouped by Public Suffix List.\nvar PAC_ROUTES = [\n", out);
    for (size_t i = 0; i < nroutes; i++)
        fprintf(out, "  \"%s\"%s\n", routes[i], i + 1 == nroutes ? "" : ",");
    fputs("];\nvar PAC_RULES = {", out);
    const char *base = NULL;
    int first = 1;
    for (size_t i = 0; i < nrules; i++) {
        if (!rules[i].keep)
            continue;
        if (!base || strcmp(base, rules[i].base)) {
            if (base) fputs("\n  },", out);
            base = rules[i].base;
            fprintf(out, "\n  \"%s\": {", base);
            first = 1;
        }
        fprintf(out, "%s\n    \"%s\": %zu", first ? "" : ",",
                rules[i].domain, route_index(rules[i].via));
        first = 0;
    }
    if (base) fputs("\n  }", out);
    fputs("\n};\n\nfunction FindProxyForURL(url, host) {\n"
          "  host = host.toLowerCase().replace(/\\.$/, \"\");\n"
          "  var own = Object.prototype.hasOwnProperty;\n"
          "  var key = host, bucket, name, dot;\n"
          "  while (true) {\n"
          "    if (own.call(PAC_RULES, key)) {\n"
          "      bucket = PAC_RULES[key];\n"
          "      name = host;\n"
          "      while (true) {\n"
          "        if (own.call(bucket, name)) return PAC_ROUTES[bucket[name]];\n"
          "        dot = name.indexOf(\".\");\n"
          "        if (dot < 0) break;\n"
          "        name = name.substring(dot + 1);\n"
          "      }\n"
          "    }\n"
          "    dot = key.indexOf(\".\");\n"
          "    if (dot < 0) break;\n"
          "    key = key.substring(dot + 1);\n"
          "  }\n", out);
    fprintf(out, "  return PAC_ROUTES[%zu];\n}\n", route_index(fallback));
    int error = ferror(out);
    if (fclose(out) || error)
        fail(NULL, "cannot build PAC");
    return body;
}

static int etag_matches(const char *header, const char *etag)
{
    if (!header)
        return 0;
    const char *p = header;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (*p == '*') {
            p++;
            while (*p == ' ' || *p == '\t') p++;
            return !*p;
        }
        if (!strncmp(p, "W/", 2)) p += 2;
        if (*p != '"') return 0;
        const char *end = strchr(p + 1, '"');
        if (!end) return 0;
        size_t len = (size_t)(end + 1 - p);
        int match = len == strlen(etag) && !memcmp(p, etag, len);
        p = end + 1;
        while (*p == ' ' || *p == '\t') p++;
        if (*p && *p != ',') return 0;
        if (match) return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *method = getenv("REQUEST_METHOD");
    cgi = method != NULL;
    if (cgi && strcmp(method, "GET") && strcmp(method, "HEAD")) {
        printf("Status: 405 Method Not Allowed\r\nAllow: GET, HEAD\r\n"
               "Cache-Control: no-store\r\nContent-Length: 0\r\n\r\n");
        return 0;
    }
    int raw = 0, check = 0, arg = 1;
    if (arg < argc && !strcmp(argv[arg], "--pac")) { raw = 1; arg++; }
    else if (arg < argc && !strcmp(argv[arg], "--check")) { check = 1; arg++; }
    if (arg < argc && !strcmp(argv[arg], "--help")) {
        puts("Usage: pac.cgi [--pac | --check] [rules.yaml]\n"
             "CGI: PAC_RULES selects the config; default is ./rules.yaml.");
        return 0;
    }
    const char *path = getenv("PAC_RULES");
    if (arg < argc) path = argv[arg++];
    if (arg != argc) fail(NULL, "too many arguments; see --help");
    load(path ? path : "rules.yaml");
    size_t kept = optimize(), length = 0;
    char *body = check ? NULL : generate(&length);
    if (check) {
        printf("OK: %zu groups, %zu unique domains, %zu retained rules\n", ngroups, nrules, kept);
    } else if (raw) {
        fwrite(body, 1, length, stdout);
    } else {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        char etag[SHA256_DIGEST_LENGTH * 2 + 3];
        if (!SHA256((const unsigned char *)body, length, digest))
            fail(NULL, "cannot hash PAC");
        etag[0] = '"';
        for (size_t i = 0; i < sizeof(digest); i++)
            snprintf(etag + 1 + i * 2, 3, "%02x", digest[i]);
        etag[sizeof(etag) - 2] = '"';
        etag[sizeof(etag) - 1] = 0;
        int cached = etag_matches(getenv("HTTP_IF_NONE_MATCH"), etag);
        printf("Status: %s\r\nETag: %s\r\nCache-Control: no-cache\r\n",
               cached ? "304 Not Modified" : "200 OK", etag);
        if (!cached)
            printf("Content-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\n"
                   "Content-Length: %zu\r\n", length);
        printf("\r\n");
        if (!cached && (!method || strcmp(method, "HEAD")))
            fwrite(body, 1, length, stdout);
    }
    free(body);
    for (size_t i = 0; i < nrules; i++) free(rules[i].domain);
    for (size_t i = 0; i < nroutes; i++) free(routes[i]);
    free(rules);
    free(routes);
    free(groups);
    yaml_document_delete(&document);
    return ferror(stdout) ? EXIT_FAILURE : EXIT_SUCCESS;
}
