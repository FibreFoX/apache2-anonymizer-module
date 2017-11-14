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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> /* for inet_pton() */
#include <string.h> /* for strsep */

#include "http_core.h" /* base stuff */
#include "http_protocol.h" /* for ap_hook_post_read_request() */
#include "http_log.h" /* logging stuff */

#include "ap_config.h" /* for ap_get_module_config() */

#include "apr_pools.h" /* for struct apr_pool_t and memory_management */
#include "apr_strings.h" /* for apr_strtok */

module AP_MODULE_DECLARE_DATA anonymizer_module;

typedef struct {
    bool enabled;
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

    return (void*) configuration;
}

static void* anonymizer_module_directory_config_merge_handler(apr_pool_t* pool, void* parent_conf, void* newlocation_conf) {
    anonymizer_cfg* mergedConfiguration = (anonymizer_cfg*) apr_pcalloc(pool, sizeof (anonymizer_cfg));
    anonymizer_cfg* directoryConfiguration2 = (anonymizer_cfg*) newlocation_conf;

    // we give full control on every level, so this deeper levels can re-enable again
    mergedConfiguration->enabled = directoryConfiguration2->enabled;

    return (void*) mergedConfiguration;
}

static void* anonymizer_module_server_config_handler(apr_pool_t* pool, server_rec* server) {
    anonymizer_cfg* configuration = (anonymizer_cfg*) apr_pcalloc(pool, sizeof (anonymizer_cfg));
    configuration->enabled = false;

    return (void*) configuration;
}

static void* anonymizer_module_server_config_merge_handler(apr_pool_t* pool, void* server1_conf, void* server2_conf) {
    anonymizer_cfg* mergedConfiguration = (anonymizer_cfg*) apr_pcalloc(pool, sizeof (anonymizer_cfg));
    anonymizer_cfg* serverConfiguration2 = (anonymizer_cfg*) server2_conf;

    mergedConfiguration->enabled = serverConfiguration2->enabled;

    return (void*) mergedConfiguration;
}

static const char* anonymizer_module_configuration_enable(cmd_parms* command_parameters, void* mconfig, int enabled) {
    anonymizer_cfg* configuration = (anonymizer_cfg*) ap_get_module_config(command_parameters->server->module_config, &anonymizer_module);
    configuration->enabled = enabled;

    return NULL;
}
//-----------------
// utils
// http://man7.org/linux/man-pages/man3/inet_pton.3.html
// https://www.ibm.com/support/knowledgecenter/en/ssw_i5_54/apis/inet_pton.htm
// https://stackoverflow.com/a/3736378/1961102
//-----------------

static bool is_ipv6(apr_pool_t* pool, char* ip) {
    in_addr_t* convertedIP = (in_addr_t*) apr_pcalloc(pool, sizeof (in_addr_t));
    return inet_pton(AF_INET6, ip, &convertedIP) == 1;
}

static bool is_ipv4(apr_pool_t* pool, char* ip) {
    in_addr_t* convertedIP = (in_addr_t*) apr_pcalloc(pool, sizeof (in_addr_t));
    return inet_pton(AF_INET, ip, &convertedIP) == 1;
}

static char* getAnonymizedIPv4(request_rec* request, char* full_ip) {
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
    newIPv4address = apr_pstrcat(request->pool, newIPv4address, "0", NULL);

    return newIPv4address;
}

static char* getAnonymizedIPv6(request_rec* request, char* full_ip) {
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
        char* anonymizedIPv4fragment = getAnonymizedIPv4(request, lastToken);
        newIPv6address = apr_pstrcat(request->pool, anonymizedIPv4fragment, NULL);
    } else {
        // add our anonymize-fragment
        newIPv6address = apr_pstrcat(request->pool, newIPv6address, "0", NULL);
    }

    return newIPv6address;
}

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

    // with Apache 2.4 the location of this information has changed
#if AP_SERVER_MAJORVERSION_NUMBER > 2 || (AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER >= 4)
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00030) "anonymizer found connection client IP %s", request->connection->client_ip);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00031) "anonymizer found request useragent IP %s", request->useragent_ip);
#else
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00032) "anonymizer found connection remote IP %s", request->connection->remote_ip);
#endif


#if AP_SERVER_MAJORVERSION_NUMBER > 2 || (AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER >= 4)
    bool isValidIpv4_clientIP = is_ipv4(request->pool, request->connection->client_ip);
    bool isValidIpv6_clientIP = is_ipv6(request->pool, request->connection->client_ip);

    if (isValidIpv4_clientIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00040) "anonymizer detected client IPv4");

        // rebuild IPv4
        char* newIPv4address = getAnonymizedIPv4(request, request->connection->client_ip);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00041) "anonymizer rebuild client IP %s", newIPv4address);

        request->connection->client_ip = apr_pstrdup(request->connection->pool, newIPv4address);
        request->connection->client_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv4address);
    }
    if (isValidIpv6_clientIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00050) "anonymizer detected IPv6");

        // rebuild IPv6
        char* newIPv6address = getAnonymizedIPv6(request, request->connection->client_ip);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00041) "anonymizer rebuild client IP %s", newIPv6address);

        request->connection->client_ip = apr_pstrdup(request->connection->pool, newIPv6address);
        request->connection->client_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv6address);
    }


    bool isValidIpv4_useragentIP = is_ipv4(request->pool, request->useragent_ip);
    bool isValidIpv6_useragentIP = is_ipv6(request->pool, request->useragent_ip);

    if (isValidIpv4_useragentIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00060) "anonymizer detected useragent IPv4");

        // rebuild IPv4
        char* newIPv4address = getAnonymizedIPv4(request, request->useragent_ip);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00061) "anonymizer rebuild useragent IP %s", newIPv4address);

        request->useragent_ip = apr_pstrdup(request->pool, newIPv4address);
        request->useragent_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv4address);
    }
    if (isValidIpv6_useragentIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00070) "anonymizer detected IPv6");

        // rebuild IPv6
        char* newIPv6address = getAnonymizedIPv6(request, request->useragent_ip);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00071) "anonymizer rebuild client IP %s", newIPv6address);

        request->useragent_ip = apr_pstrdup(request->connection->pool, newIPv6address);
        request->useragent_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv6address);
    }
#else
    bool isValidIpv4_remoteIP = is_ipv4(request->pool, request->connection->remote_ip);
    bool isValidIpv6_remoteIP = is_ipv6(request->pool, request->connection->remote_ip);
    if (isValidIpv4_remoteIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00080) "anonymizer detected remote IPv4");

        // rebuild IPv4
        char* newIPv4address = getAnonymizedIPv4(request, request->connection->remote_ip);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00081) "anonymizer rebuild remote IP %s", newIPv4address);

        request->connection->remote_ip = apr_pstrdup(request->pool, newIPv4address);
        request->connection->remote_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv4address);
    }
    if (isValidIpv6_remoteIP) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00090) "anonymizer detected remote IPv6");

        // rebuild IPv6
        char* newIPv6address = getAnonymizedIPv6(request, request->connection->remote_ip);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, request, APLOGNO(00091) "anonymizer rebuild remote IP %s", newIPv6address);

        request->connection->remote_ip = apr_pstrdup(request->connection->pool, newIPv6address);
        request->connection->remote_addr->sa.sin.sin_addr.s_addr = inet_addr(newIPv6address);
    }
#endif

    // as we are some middleware-handler, let others do their work too
    return DECLINED;
}

//-------------
// module-setup
//-------------

// directives
static const command_rec anonymizer_module_directives[] = {
    AP_INIT_FLAG("Anonymize", anonymizer_module_configuration_enable, NULL, RSRC_CONF, "Enable anonymization of the requests IP address"),
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