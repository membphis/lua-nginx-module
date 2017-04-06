
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

/* keys in Lua thread for fetching args and nargs in set_by_lua* */

#define ngx_http_lua_nargs_key  "__ngx_nargs"
#define ngx_http_lua_args_key  "__ngx_args"

static ngx_int_t ngx_http_lua_intercept_log_by_chunk(lua_State *L, ngx_http_request_t *r);

ngx_http_variable_value_t args[2];

static void
ngx_http_lua_intercept_log_by_lua_env(lua_State *L, ngx_http_request_t *r)
{
    /*  set nginx request pointer to current lua thread's globals table */
    ngx_http_lua_set_req(L, r);

    //lua_pushnumber(L, 22222);
    //lua_setglobal(L, "log_level");
    //lua_pushstring(L, "log dddddddd");
    //lua_setglobal(L, "log_data");
    args[0].data = "112233";
    args[0].valid=1;
    args[0].len = 6;
    args[1].data = "4444444444";
    args[1].valid=1;
    args[1].len = 10;

    lua_pushinteger(L, 2);
    lua_setglobal(L, ngx_http_lua_nargs_key);

    lua_pushlightuserdata(L, args);
    lua_setglobal(L, ngx_http_lua_args_key);

    //lua_pushlightuserdata(L, args);
    //lua_setglobal(L, ngx_http_lua_args_key);

    /**
     * we want to create empty environment for current script
     *
     * newt = {}
     * newt["_G"] = newt
     * setmetatable(newt, {__index = _G})
     *
     * if a function or symbol is not defined in our env, __index will lookup
     * in the global env.
     *
     * all variables created in the script-env will be thrown away at the end
     * of the script run.
     * */
    ngx_http_lua_create_new_globals_table(L, 0 /* narr */, 1 /* nrec */);

    /*  {{{ make new env inheriting main thread's globals table */
    lua_createtable(L, 0, 1);    /*  the metatable for the new env */
    ngx_http_lua_get_globals_table(L);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);    /*  setmetatable({}, {__index = _G}) */
    /*  }}} */

    lua_setfenv(L, -2);    /*  set new running env for the code closure */
}


ngx_int_t
ngx_http_lua_intercept_log_handler(ngx_log_t *log,
    ngx_uint_t level, void *buf, size_t n)
{
    //ngx_http_lua_main_conf_t     *lmcf;
    ngx_http_lua_loc_conf_t     *llcf;
    ngx_http_request_t           *r;
    ngx_http_log_ctx_t           *ctx;

    if (log->handler == ngx_http_log_error) {
        ctx = log->data;
        r = ctx->request;
    } else {
        printf("intercept_log only support http log now\n");
        return NGX_DECLINED;
    }

    printf("intercept log ===> : %s\n", (const char *)buf);

    //lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);
    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    return llcf->intercept_log_handler(r, level, buf, n);
}


ngx_int_t
ngx_http_lua_intercept_log_handler_inline(ngx_http_request_t *r,
    ngx_uint_t level, void *buf, size_t n)
{
    lua_State                   *L;
    ngx_int_t                    rc;
    ngx_http_lua_loc_conf_t     *llcf;

    dd("intercept log by lua inline");

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    L = ngx_http_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = ngx_http_lua_cache_loadbuffer(r->connection->log, L,
                                       llcf->intercept_log_src.value.data,
                                       llcf->intercept_log_src.value.len,
                                       llcf->intercept_log_src_key,
                                       (const char *) llcf->intercept_log_chunkname);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_lua_intercept_log_by_chunk(L, r);
}


ngx_int_t
ngx_http_lua_intercept_log_handler_file(ngx_http_request_t *r,
    ngx_uint_t level, void *buf, size_t n)
{
    lua_State                       *L;
    ngx_int_t                        rc;
    u_char                          *script_path;
    ngx_http_lua_loc_conf_t         *llcf;
    ngx_str_t                        eval_src;

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    if (ngx_http_complex_value(r, &llcf->intercept_log_src, &eval_src) != NGX_OK) {
        return NGX_ERROR;
    }

    script_path = ngx_http_lua_rebase_path(r->pool, eval_src.data,
                                           eval_src.len);

    if (script_path == NULL) {
        return NGX_ERROR;
    }

    L = ngx_http_lua_get_lua_vm(r, NULL);

    /*  load Lua script file (w/ cache)        sp = 1 */
    rc = ngx_http_lua_cache_loadfile(r->connection->log, L, script_path,
                                     llcf->intercept_log_src_key);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_lua_intercept_log_by_chunk(L, r);
}


ngx_int_t
ngx_http_lua_intercept_log_by_chunk(lua_State *L, ngx_http_request_t *r)
{
    size_t           i;
    ngx_int_t        rc;
    u_char          *err_msg;
    size_t           len;
#if (NGX_PCRE)
    ngx_pool_t      *old_pool;
#endif

    /*  set Lua VM panic handler */
    lua_atpanic(L, ngx_http_lua_atpanic);

    NGX_LUA_EXCEPTION_TRY {

        /* initialize nginx context in Lua VM, code chunk at stack top sp = 1 */
        ngx_http_lua_intercept_log_by_lua_env(L, r);

        //for (i = 0; i < 2; i++) {
        //    lua_pushlstring(L, (const char *) args[i].data, args[i].len);
        //    printf("logby %s\n", args[i].data);
        //}
        lua_pushlstring(L, "3333333", 5);
        lua_pushlstring(L, "4444444", 5);

#if (NGX_PCRE)
        /* XXX: work-around to nginx regex subsystem */
        old_pool = ngx_http_lua_pcre_malloc_init(r->pool);
#endif

        lua_pushcfunction(L, ngx_http_lua_traceback);
        lua_insert(L, 1);  /* put it under chunk and args */

        /*  protected call user code */
        rc = lua_pcall(L, 2, 1, 1);

        lua_remove(L, 1);  /* remove traceback function */

#if (NGX_PCRE)
        /* XXX: work-around to nginx regex subsystem */
        ngx_http_lua_pcre_malloc_done(old_pool);
#endif

        if (rc != 0) {
            /*  error occurred when running loaded code */
            err_msg = (u_char *) lua_tolstring(L, -1, &len);

            if (err_msg == NULL) {
                err_msg = (u_char *) "unknown reason";
                len = sizeof("unknown reason") - 1;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "failed to run intercept_log_by_lua*: %*s", len, err_msg);

            lua_settop(L, 0);    /*  clear remaining elems on stack */

            return NGX_ERROR;
        }

    } NGX_LUA_EXCEPTION_CATCH {

        dd("nginx execution restored");
        return NGX_ERROR;
    }

    /*  clear Lua stack */
    lua_settop(L, 0);

    return NGX_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
