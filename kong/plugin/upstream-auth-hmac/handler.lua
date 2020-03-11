local BasePlugin = require "kong.plugins.base_plugin"
local openssl_hmac = require "openssl.hmac"

local PluginHandler = BasePlugin:extend()
PluginHandler.PRIORITY = 851 -- cf. upstream-auth-basic.PRIORITY == 850
PluginHandler.VERSION = "0.1.0"

function PluginHandler:new()
    PluginHandler.super.new(self, "upstream-auth-hmac")
end

function PluginHandler:access(conf)
    PluginHandler.super.access(self)

    local username = conf.username
    local secret = conf.secret

    local date = ngx.http_time(ngx.now())
    local algorithm = "hmac-sha256"
    local hmac_headers = "date request-line"
    local method = ngx.req.get_method()
    local path_with_query = kong.request.get_path_with_query()
    -- local path_with_query = ngx.var.request_uri

    local msg = fmt("date: %s\n%s %s HTTP/%s", date, method, path_with_query, "1.1")
    local signiture = openssl_hmac.new(secret, "sha256"):final(msg)
    local authorizationHeader = fmt("hmac username=\"%s\", algorithm=\"%s\", headers=\"%s\", signature=\"%s\"",
                                    token, algorithm, hmac_headers, ngx.encode_base64(signiture))

    -- ngx.log(ngx.WARN, fmt("header: %s", authorizationHeader))
    ngx.req.set_header("Date", date)
    ngx.req.set_header("Authorization", authorizationHeader)
end


return PluginHandler