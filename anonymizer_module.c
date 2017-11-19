/*
 * Copyright 2017 Danny Althoff
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h> /* for bool */
#include <netinet/in.h> /* for in_addr_t */
#include <arpa/inet.h> /* for inet_pton() */

#include "http_core.h" /* base stuff */
#include "http_protocol.h" /* for ap_hook_post_read_request() */
#include "http_log.h" /* logging stuff */

#include "ap_config.h" /* for ap_get_module_config() */

#include "apr_pools.h" /* for struct apr_pool_t and memory management */
#include "apr_strings.h" /* for apr_strtok, apr_pstrdup, apr_pstrcat */

module AP_MODULE_DECLARE_DATA anonymizer_module;

typedef struct {
    // for enabling/disabling the module
    bool enabled;
    // last part of the IP, make it adjustable (defaults to 0)
    char* anonymizeFragmentV4;
    char* anonymizeFragmentV6;
} anonymizer_cfg;

/*
 inspirations:
 * https://github.com/kawasima/mod_gearman/blob/master/mod_gearman.c
 * https://github.com/moba/libapache-mod-removeip/blob/master/apache2.0/mod_removeip.c
 * https://github.com/skx/mod_blacklist/blob/master/mod_blacklist.c
 * https://github.com/discont/mod_realip2/blob/master/mod_realip2.c
 * https://github.com/discont/mod_realip2
 * https://github.com/nmaier/mod_xsendfile/blob/master/mod_xsendfile.c
 * https://github.com/waleedq/libapache2-mod-less_beta1/blob/master/src/mod_less.c
 */
//-----------------------
// configuration handling
//-----------------------

static void* anonymizer_module_directory_config_handler(apr_pool_t* pool, char* dirspec) {
    anonymizer_cfg* configuration = (anonymizer_cfg*) apr_pcalloc(pool, sizeof (anonymizer_cfg));
    configuration->enabled = false;
    configuration->anonymizeFragmentV4 = "0";
    configuration->anonymizeFragmentV6 = "0";

    return (void*) configuration;
}

static void* anonymizer_module_directory_config_merge_handler(apr_pool_t* pool, void* parent_conf, void* newlocation_conf) {
    anonymizer_cfg* mergedConfiguration = (anonymizer_cfg*) apr_pcalloc(pool, sizeof (anonymizer_cfg));
    anonymizer_cfg* directoryConfiguration2 = (anonymizer_cfg*) newlocation_conf;

    // we give full control on every level, so this deeper levels can re-enable again
    mergedConfiguration->enabled = directoryConfiguration2->enabled;
    mergedConfiguration->anonymizeFragmentV4 = apr_pstrdup(pool, directoryConfiguration2->anonymizeFragmentV4);
    mergedConfiguration->anonymizeFragmentV6 = apr_pstrdup(pool, directoryConfiguration2->anonymizeFragmentV6);

    return (void*) mergedConfiguration;
}

static void* anonymizer_module_server_config_handler(apr_pool_t* pool, server_rec* server) {
    anonymizer_cfg* configuration = (anonymizer_cfg*) apr_pcalloc(pool, sizeof (anonymizer_cfg));
    configuration->enabled = false;
    configuration->anonymizeFragmentV4 = "0";
    configuration->anonymizeFragmentV6 = "0";

    return (void*) configuration;
}

static void* anonymizer_module_server_config_merge_handler(apr_pool_t* pool, void* server1_conf, void* server2_conf) {
    anonymizer_cfg* mergedConfiguration = (anonymizer_cfg*) apr_pcalloc(pool, sizeof (anonymizer_cfg));
    anonymizer_cfg* serverConfiguration2 = (anonymizer_cfg*) server2_conf;

    mergedConfiguration->enabled = serverConfiguration2->enabled;
    mergedConfiguration->anonymizeFragmentV4 = apr_pstrdup(pool, serverConfiguration2->anonymizeFragmentV4);
    mergedConfiguration->anonymizeFragmentV6 = apr_pstrdup(pool, serverConfiguration2->anonymizeFragmentV6);

    return (void*) mergedConfiguration;
}

static const char* anonymizer_module_configuration_enable(cmd_parms* command_parameters, void* mconfig, int enabled) {
    anonymizer_cfg* configuration = (anonymizer_cfg*) ap_get_module_config(command_parameters->server->module_config, &anonymizer_module);
    configuration->enabled = enabled;

    return NULL;
}

static const char* anonymizer_module_configuration_fragment(cmd_parms* command_parameters, void* mconfig, const char *arg) {
    anonymizer_cfg* configuration = (anonymizer_cfg*) ap_get_module_config(command_parameters->server->module_config, &anonymizer_module);
    char* copyOfOriginalParameter = apr_pstrdup(command_parameters->temp_pool, arg);
    int possibleValidNumber = atoi(copyOfOriginalParameter);
    if (possibleValidNumber >= 0 && possibleValidNumber <= 255) {
        // both IPv4 and IPv6 are limited to IPv4-range, only 0-255 is valid for IPv4
        configuration->anonymizeFragmentV4 = apr_pstrdup(command_parameters->temp_pool, arg);
        configuration->anonymizeFragmentV6 = apr_pstrdup(command_parameters->temp_pool, arg);
    }

    return NULL;
}

static const char* anonymizer_module_configuration_fragmentV4(cmd_parms* command_parameters, void* mconfig, const char *arg) {
    anonymizer_cfg* configuration = (anonymizer_cfg*) ap_get_module_config(command_parameters->server->module_config, &anonymizer_module);
    char* copyOfOriginalParameter = apr_pstrdup(command_parameters->temp_pool, arg);
    int possibleValidNumber = atoi(copyOfOriginalParameter);
    if (possibleValidNumber >= 0 && possibleValidNumber <= 255) {
        // only 0-255 is valid for IPv4
        configuration->anonymizeFragmentV4 = apr_pstrdup(command_parameters->temp_pool, arg);
    }

    return NULL;
}

static const char* anonymizer_module_configuration_fragmentV6(cmd_parms* command_parameters, void* mconfig, const char *arg) {
    anonymizer_cfg* configuration = (anonymizer_cfg*) ap_get_module_config(command_parameters->server->module_config, &anonymizer_module);
    configuration->anonymizeFragmentV6 = apr_pstrdup(command_parameters->temp_pool, arg);

    return NULL;
}
//-----------------
// utils
// http://man7.org/linux/man-pages/man3/inet_pton.3.html
// https://www.ibm.com/support/knowledgecenter/en/ssw_i5_54/apis/inet_pton.htm
// https://stackoverflow.com/a/3736378/1961102
//-----------------

#if APR_HAVE_IPV6

static bool is_ipv6(apr_pool_t* pool, char* ip) {
    // use proper type for ipv6
    struct in6_addr* convertedIP = (struct in6_addr*) apr_pcalloc(pool, sizeof (struct in6_addr*));
    return inet_pton(AF_INET6, ip, &convertedIP) == 1;
}
#endif

static bool is_ipv4(apr_pool_t* pool, char* ip) {
    in_addr_t* convertedIP = (in_addr_t*) apr_pcalloc(pool, sizeof (in_addr_t));
    return inet_pton(AF_INET, ip, &convertedIP) == 1;
}

/**
 * Separate @input by @delimiter, custom workaround for different problems:
 * - apr_strtok/strtok does skip empty tokens
 * - No apr_strsep-implementation
 * - strsep is not c99 conform, not there on every system-architecture
 * 
 * @param input
 * @param delimiter single char (unlike apr_strtop, we only need one single char for our purpose)
 * @param remaining
 * @return returns next token (string up to but not including @delimiter)
 */
static char* strseparate(apr_pool_t* pool, char* input, const char* delimiter, char** remaining) {
    if (input == NULL && remaining == NULL || delimiter == NULL) {
        return NULL;
    }

    char* inputToWorkOn = input;

    return NULL;
}

static char* getAnonymizedIPv4(request_rec* request, char* full_ip, char* anonymizeFragment) {
    char* newIPv4address = "";

    char* ipToWorkOn = apr_pstrdup(request->pool, full_ip);
    char* strtok_state;
    char* lastToken;

    while ((lastToken = apr_strtok(ipToWorkOn, ".", &strtok_state)) != NULL) {
        ipToWorkOn = NULL;
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(01001) "anonymizer detected ipv4 part %s", lastToken);
        if (strtok_state[0] == '\0') {
            // skip this entry, because it's the last remaining fragment, when having last token
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(01002) "anonymizer detected ipv4 LAST part %s", lastToken);
        } else {
            newIPv4address = apr_pstrcat(request->pool, newIPv4address, lastToken, ".", NULL);
        }
    }

    // add our anonymize-fragment
    newIPv4address = apr_pstrcat(request->pool, newIPv4address, anonymizeFragment, NULL);

    return newIPv4address;
}
#if APR_HAVE_IPV6

static char* getAnonymizedIPv6(request_rec* request, char* full_ip, char* anonymizeFragmentV6, char* anonymizeFragmentV4) {
    char* newIPv6address = "";

    char* ipToWorkOn = apr_pstrdup(request->pool, full_ip);
    char* strtok_state;
    char* lastToken;

    while ((lastToken = apr_strtok(ipToWorkOn, ":", &strtok_state)) != NULL) {
        ipToWorkOn = NULL;
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(01001) "anonymizer detected ipv6 part %s", lastToken);
        if (strtok_state[0] == '\0') {
            // skip this entry, because it's the last remaining fragment, when having last token
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(01002) "anonymizer detected ipv6 LAST part %s", lastToken);
        } else {
            newIPv6address = apr_pstrcat(request->pool, newIPv6address, lastToken, ":", NULL);
        }
    }

    // last part can be ipv4, so check for it to anonymize
    if (is_ipv4(request->pool, lastToken)) {
        char* anonymizedIPv4fragment = getAnonymizedIPv4(request, lastToken, anonymizeFragmentV4);
        newIPv6address = apr_pstrcat(request->pool, anonymizedIPv4fragment, NULL);
    } else {
        // add our anonymize-fragment
        newIPv6address = apr_pstrcat(request->pool, newIPv6address, anonymizeFragmentV6, NULL);
    }

    return newIPv6address;
}
#endif

//-----------------
// request handling
//-----------------

static int anonymizer_module_request_handler(request_rec* request) {
    anonymizer_cfg* configuration = (anonymizer_cfg*) ap_get_module_config(request->server->module_config, &anonymizer_module);

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00010) "checking anonymizer state");

    // check if we should work on this request
    if (configuration->enabled == false) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00020) "anonymizer disabled");
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00021) "anonymizer enabled");

#if APR_HAVE_IPV6
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00022) "anonymizer uses APR with IPv6 support enabled");
#endif // APR_HAVE_IPV6

    // with Apache 2.4 the location of this information has changed
#if AP_SERVER_MAJORVERSION_NUMBER > 2 || (AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER >= 4)
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00030) "anonymizer found connection client IP %s", request->connection->client_ip);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00031) "anonymizer found request useragent IP %s", request->useragent_ip);
#else
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00032) "anonymizer found connection remote IP %s", request->connection->remote_ip);
#endif


#if AP_SERVER_MAJORVERSION_NUMBER > 2 || (AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER >= 4)
    bool isValidIpv4_clientIP = is_ipv4(request->pool, request->connection->client_ip);
    if (isValidIpv4_clientIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00040) "anonymizer detected client IPv4");

        // rebuild IPv4
        char* newIPv4address = getAnonymizedIPv4(request, request->connection->client_ip, configuration->anonymizeFragmentV4);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00041) "anonymizer rebuild client IP %s", newIPv4address);

        request->connection->client_ip = apr_pstrdup(request->connection->pool, newIPv4address);
        request->connection->client_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv4address);
    }

#if APR_HAVE_IPV6
    bool isValidIpv6_clientIP = is_ipv6(request->pool, request->connection->client_ip);
    if (isValidIpv6_clientIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00050) "anonymizer detected IPv6");

        // rebuild IPv6
        char* newIPv6address = getAnonymizedIPv6(request, request->connection->client_ip, configuration->anonymizeFragmentV6, configuration->anonymizeFragmentV4);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00041) "anonymizer rebuild client IP %s", newIPv6address);

        request->connection->client_ip = apr_pstrdup(request->connection->pool, newIPv6address);
        request->connection->client_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv6address);
    }
#endif // APR_HAVE_IPV6


    bool isValidIpv4_useragentIP = is_ipv4(request->pool, request->useragent_ip);

    if (isValidIpv4_useragentIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00060) "anonymizer detected useragent IPv4");

        // rebuild IPv4
        char* newIPv4address = getAnonymizedIPv4(request, request->useragent_ip, configuration->anonymizeFragmentV4);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00061) "anonymizer rebuild useragent IP %s", newIPv4address);

        request->useragent_ip = apr_pstrdup(request->pool, newIPv4address);
        request->useragent_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv4address);
    }
#if APR_HAVE_IPV6
    bool isValidIpv6_useragentIP = is_ipv6(request->pool, request->useragent_ip);
    if (isValidIpv6_useragentIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00070) "anonymizer detected IPv6");

        // rebuild IPv6
        char* newIPv6address = getAnonymizedIPv6(request, request->useragent_ip, configuration->anonymizeFragmentV6, configuration->anonymizeFragmentV4);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00071) "anonymizer rebuild client IP %s", newIPv6address);

        request->useragent_ip = apr_pstrdup(request->connection->pool, newIPv6address);
        request->useragent_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv6address);
    }
#endif // APR_HAVE_IPV6

#else // apache 2.2 below
    bool isValidIpv4_remoteIP = is_ipv4(request->pool, request->connection->remote_ip);
    if (isValidIpv4_remoteIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00080) "anonymizer detected remote IPv4");

        // rebuild IPv4
        char* newIPv4address = getAnonymizedIPv4(request, request->connection->remote_ip, configuration->anonymizeFragmentV4);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00081) "anonymizer rebuild remote IP %s", newIPv4address);

        request->connection->remote_ip = apr_pstrdup(request->pool, newIPv4address);
        request->connection->remote_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv4address);
    }

#if APR_HAVE_IPV6
    bool isValidIpv6_remoteIP = is_ipv6(request->pool, request->connection->remote_ip);
    if (isValidIpv6_remoteIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00090) "anonymizer detected remote IPv6");

        // rebuild IPv6
        char* newIPv6address = getAnonymizedIPv6(request, request->connection->remote_ip, configuration->anonymizeFragmentV6, configuration->anonymizeFragmentV4);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00091) "anonymizer rebuild remote IP %s", newIPv6address);

        request->connection->remote_ip = apr_pstrdup(request->connection->pool, newIPv6address);
        request->connection->remote_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv6address);
    }
#endif // APR_HAVE_IPV6

#endif // apache 2.2 VS apache 2.4 switch

    // as we are some middleware-handler, let others do their work too
    return DECLINED;
}

//-------------
// module-setup
//-------------

// directives
static const command_rec anonymizer_module_directives[] = {
    AP_INIT_FLAG("Anonymize", anonymizer_module_configuration_enable, NULL, OR_OPTIONS, "Enable anonymization of the requests IP address"),
    AP_INIT_TAKE1("AnonymizeFragment", anonymizer_module_configuration_fragment, NULL, OR_OPTIONS, "Sets the replacement part for anonymizing IP address (IPv4 + IPv6), default is 0 (zero)"),
    AP_INIT_TAKE1("AnonymizeFragmentv4", anonymizer_module_configuration_fragmentV4, NULL, OR_OPTIONS, "Sets the replacement part for anonymizing IPv4 address, default is 0 (zero)"),
    AP_INIT_TAKE1("AnonymizeFragmentv6", anonymizer_module_configuration_fragmentV6, NULL, OR_OPTIONS, "Sets the replacement part for anonymizing IPv6 address, default is 0 (zero)"),
    {NULL}
};

// hook-registration

static void anonymizer_module_register_hooks(apr_pool_t* pool) {

    // make this BEFORE mod_proxy acts
    static const char* hooksAfter[] = {"mod_proxy.c", NULL};
    static const char* hooksBefore[] = {"mod_log_forensic.c", NULL};

    // using APR_HOOK_REALLY_FIRST as other modules might get the IP when using APR_HOOK_FIRST
    // but do not run before log_forensic ! its there for a reason
    ap_hook_post_read_request(anonymizer_module_request_handler, hooksBefore, hooksAfter, APR_HOOK_REALLY_FIRST);
}

/*
    https://httpd.apache.org/docs/2.4/developer/modguide.html
 */
module AP_MODULE_DECLARE_DATA anonymizer_module = {
    STANDARD20_MODULE_STUFF,
    anonymizer_module_directory_config_handler, /* Per-directory configuration handler */
    anonymizer_module_directory_config_merge_handler, /* Merge handler for per-directory configurations */
    anonymizer_module_server_config_handler, /* Per-server configuration handler */
    anonymizer_module_server_config_merge_handler, /* Merge handler for per-server configurations */
    anonymizer_module_directives, /* Any directives we may have for httpd */
    anonymizer_module_register_hooks /* Our hook registering function */
};