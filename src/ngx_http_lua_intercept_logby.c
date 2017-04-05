
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


static ngx_int_t ngx_http_lua_intercept_log_by_chunk(lua_State *L, ngx_pool_t *pool,
    ngx_log_t *log);

static void
ngx_http_lua_intercept_log_by_lua_env(lua_State *L)
{
    /*  set nginx request pointer to current lua thread's globals table */
    //ngx_http_lua_set_req(L, r);

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


ngx_int_t ngx_http_lua_intercept_log_handler(ngx_log_t *log,
    ngx_uint_t level, void *buf, size_t n)
{
    ngx_http_lua_main_conf_t     *lmcf;

    lmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_lua_module);

    return lmcf->intercept_log_handler(log, level, buf, n);;
}


ngx_int_t
ngx_http_lua_intercept_log_handler_inline(ngx_log_t *log,
    ngx_uint_t level, void *buf, size_t n)
{
    lua_State                   *L;
    ngx_int_t                    rc;
    ngx_http_lua_main_conf_t     *lmcf;

    dd("intercept log by lua inline");

    lmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_lua_module);

    L = lmcf->lua;

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = ngx_http_lua_cache_loadbuffer(log, L,
                                       lmcf->intercept_log_src.value.data,
                                       lmcf->intercept_log_src.value.len,
                                       lmcf->intercept_log_src_key,
                                       (const char *) lmcf->intercept_log_chunkname);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_lua_intercept_log_by_chunk(L, ngx_cycle->pool, log);
}


//ngx_int_t
//ngx_http_lua_intercept_log_handler_file(ngx_log_t *log,
//    ngx_uint_t level, void *buf, size_t n)
//{
//    lua_State                       *L;
//    ngx_int_t                        rc;
//    u_char                          *script_path;
//    ngx_http_lua_main_conf_t        *lmcf;
//    ngx_str_t                        eval_src;

//    lmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_lua_module);

//    if (ngx_http_complex_value(r, &lmcf->intercept_log_src, &eval_src) != NGX_OK) {
//        return NGX_ERROR;
//    }

//    script_path = ngx_http_lua_rebase_path(ngx_cycle->pool, eval_src.data,
//                                           eval_src.len);

//    if (script_path == NULL) {
//        return NGX_ERROR;
//    }

//    L = lmcf->lua;

//    /*  load Lua script file (w/ cache)        sp = 1 */
//    rc = ngx_http_lua_cache_loadfile(log, L, script_path,
//                                     lmcf->intercept_log_src_key);
//    if (rc != NGX_OK) {
//        return NGX_ERROR;
//    }

//    return ngx_http_lua_intercept_log_by_chunk(L, ngx_cycle->pool, log);
//}


ngx_int_t
ngx_http_lua_intercept_log_by_chunk(lua_State *L, ngx_pool_t *pool, ngx_log_t *log)
{
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
        ngx_http_lua_intercept_log_by_lua_env(L);

#if (NGX_PCRE)
        /* XXX: work-around to nginx regex subsystem */
        old_pool = ngx_http_lua_pcre_malloc_init(pool);
#endif

        lua_pushcfunction(L, ngx_http_lua_traceback);
        lua_insert(L, 1);  /* put it under chunk and args */

        /*  protected call user code */
        rc = lua_pcall(L, 0, 1, 1);

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

            ngx_log_error(NGX_LOG_ERR, log, 0,
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
