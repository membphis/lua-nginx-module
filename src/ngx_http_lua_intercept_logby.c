
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_directive.h"
#include "ngx_http_lua_logby.h"
#include "ngx_http_lua_intercept_logby.h"
#include "ngx_http_lua_exception.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_pcrefix.h"
#include "ngx_http_lua_time.h"
#include "ngx_http_lua_log.h"
#include "ngx_http_lua_regex.h"
#include "ngx_http_lua_cache.h"
#include "ngx_http_lua_headers.h"
#include "ngx_http_lua_variable.h"
#include "ngx_http_lua_string.h"
#include "ngx_http_lua_misc.h"
#include "ngx_http_lua_consts.h"
#include "ngx_http_lua_shdict.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_exception.h"
#if (NGX_HTTP_LUA_HAVE_MALLOC_TRIM)
#include <malloc.h>
#endif


ngx_int_t
ngx_http_lua_intercept_log_handler(ngx_log_t *log,
    ngx_uint_t level, void *buf, size_t n)
{
    ngx_http_lua_loc_conf_t      *llcf;
    ngx_http_request_t           *r;
    ngx_http_log_ctx_t           *log_ctx;
    ngx_http_lua_ctx_t           *ctx;
    ngx_array_t                  *logs;
    ngx_str_t                    *new_log;

    if (log->handler == ngx_http_log_error) {
        log_ctx = log->data;
        r = log_ctx->request;
    } else {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx->context == NGX_HTTP_LUA_CONTEXT_LOG) {
        return NGX_DECLINED;
    }

    logs = r->intercept_logs;
    if (!logs) {
        logs = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
        if (logs == NULL) {
            return NGX_ERROR;
        }

        r->intercept_logs = logs;
    } else if (logs->nelts >= 4) {
        return NGX_DECLINED;
    }

    new_log = ngx_array_push(logs);
    new_log->data = ngx_palloc(r->pool, n);
    if (new_log->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(new_log->data, buf, n);
    new_log->len = n;

    return NGX_OK;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
