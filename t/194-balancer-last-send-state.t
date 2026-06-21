# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5);

no_long_string();
run_tests();

__DATA__

=== TEST 1: first balancer run has no last send state
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;;";

    upstream backend {
        server 0.0.0.1;

        balancer_by_lua_block {
            local ffi = require "ffi"
            local C = ffi.C

ffi.cdef[[
int ngx_http_lua_ffi_balancer_get_last_send_state(ngx_http_request_t *r,
    long *bytes, char **err);
]]

            local base = require "resty.core.base"
            local r = base.get_request()
            local bytes = ffi.new("long[1]")
            local errmsg = ffi.new("char *[1]")
            local rc = C.ngx_http_lua_ffi_balancer_get_last_send_state(r,
                                                                       bytes,
                                                                       errmsg)

            if rc < 0 then
                ngx.log(ngx.ERR, "get last send state failed: ",
                        ffi.string(errmsg[0]))
                return
            end

            local states = {
                [0] = "none",
                [1] = "partial",
                [2] = "complete",
            }

            ngx.log(ngx.ERR, "last send state: ", states[rc],
                    ", bytes: ", tonumber(bytes[0]))

            local balancer = require "ngx.balancer"
            assert(balancer.set_current_peer("127.0.0.1", 81))
        }
    }
--- config
    location = /t {
        proxy_pass http://backend;
    }
--- request
    GET /t
--- response_body_like: 502 Bad Gateway
--- error_code: 502
--- error_log
last send state: none, bytes: 0
--- no_error_log
get last send state failed
[alert]



=== TEST 2: connection failure before sending bytes reports none
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;;";

    upstream backend {
        server 0.0.0.1;

        balancer_by_lua_block {
            local ffi = require "ffi"
            local C = ffi.C

ffi.cdef[[
int ngx_http_lua_ffi_balancer_get_last_send_state(ngx_http_request_t *r,
    long *bytes, char **err);
]]

            local base = require "resty.core.base"
            local r = base.get_request()
            local bytes = ffi.new("long[1]")
            local errmsg = ffi.new("char *[1]")
            local rc = C.ngx_http_lua_ffi_balancer_get_last_send_state(r,
                                                                       bytes,
                                                                       errmsg)

            if rc < 0 then
                ngx.log(ngx.ERR, "get last send state failed: ",
                        ffi.string(errmsg[0]))
                return
            end

            local states = {
                [0] = "none",
                [1] = "partial",
                [2] = "complete",
            }

            ngx.ctx.tries = (ngx.ctx.tries or 0) + 1
            ngx.log(ngx.ERR, "try: ", ngx.ctx.tries,
                    ", last send state: ", states[rc],
                    ", bytes: ", tonumber(bytes[0]))

            local balancer = require "ngx.balancer"
            if ngx.ctx.tries == 1 then
                assert(balancer.set_more_tries(1))
            end

            assert(balancer.set_current_peer("127.0.0.1", 81))
        }
    }
--- config
    location = /t {
        proxy_next_upstream error timeout;
        proxy_pass http://backend;
    }
--- request
    GET /t
--- response_body_like: 502 Bad Gateway
--- error_code: 502
--- grep_error_log eval: qr/try: \d, last send state: \w+, bytes: \d+/
--- grep_error_log_out
try: 1, last send state: none, bytes: 0
try: 2, last send state: none, bytes: 0
--- no_error_log
get last send state failed
[alert]



=== TEST 3: completed request body reports complete on retry
--- http_config
    lua_package_path "../lua-resty-core/lib/?.lua;;";

    server {
        listen 127.0.0.1:$TEST_NGINX_RAND_PORT_1;

        location / {
            return 503;
        }
    }

    upstream backend {
        server 0.0.0.1;

        balancer_by_lua_block {
            local ffi = require "ffi"
            local C = ffi.C

ffi.cdef[[
int ngx_http_lua_ffi_balancer_get_last_send_state(ngx_http_request_t *r,
    long *bytes, char **err);
]]

            local base = require "resty.core.base"
            local r = base.get_request()
            local bytes = ffi.new("long[1]")
            local errmsg = ffi.new("char *[1]")
            local rc = C.ngx_http_lua_ffi_balancer_get_last_send_state(r,
                                                                       bytes,
                                                                       errmsg)

            if rc < 0 then
                ngx.log(ngx.ERR, "get last send state failed: ",
                        ffi.string(errmsg[0]))
                return
            end

            local states = {
                [0] = "none",
                [1] = "partial",
                [2] = "complete",
            }

            ngx.ctx.tries = (ngx.ctx.tries or 0) + 1
            ngx.log(ngx.ERR, "try: ", ngx.ctx.tries,
                    ", last send state: ", states[rc],
                    ", bytes: ", tonumber(bytes[0]))

            local balancer = require "ngx.balancer"
            if ngx.ctx.tries == 1 then
                assert(balancer.set_more_tries(1))
            end

            assert(balancer.set_current_peer("127.0.0.1",
                                             $TEST_NGINX_RAND_PORT_1))
        }
    }
--- config
    location = /t {
        proxy_next_upstream http_503 non_idempotent;
        proxy_pass http://backend;
    }
--- request
    POST /t
    hello world
--- response_body_like: 503 Service Temporarily Unavailable
--- error_code: 503
--- grep_error_log eval: qr/try: \d, last send state: \w+, bytes: \d+/
--- grep_error_log_out eval
qr/^try: 1, last send state: none, bytes: 0
try: 2, last send state: complete, bytes: [1-9]\d*$/
--- no_error_log
get last send state failed
[alert]
