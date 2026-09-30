# easypac

单文件 C CGI：读取 YAML，用 PSL 归类、排序并精简规则，生成 PAC，支持 ETag / 304。配置修改后，下次请求生效。

## 配置

```yaml
直连:
  - baidu.com

"走代理的站点":
  - example.com

proxy:
  - method: direct
    domains: [直连]
  - method: http
    url: 127.0.0.1
    port: 7890
    domains: ["走代理的站点"]

default:
  method: socks5
  url: 127.0.0.1
  port: 1080
```

顶层只保留 `proxy` 和 `default`。其余键是自定义组名，使用 YAML 标量写法，支持中文、空格、引号、流式列表与锚点引用；组的值必须是域名列表。`proxy` 是出口列表，`domains` 引用一个或多个组，`default` 是未匹配时的出口。未引用的组不参与匹配。

`method` 支持 `direct`、`http`、`https`、`socks`、`socks4`、`socks5`，大小写不敏感。`direct` 只写 `method`；其他方式需要 `url` 和 `port`（1–65535）。`url` 是代理服务器的主机名或 IP 地址，例如 `proxy.example.com`、`127.0.0.1`、`::1`；IPv6 也可以写成 `"[::1]"`。这里填写的地址由 PAC 使用者连接，`127.0.0.1` 指客户端本机。

域名匹配自身及其子域，更具体的规则优先。域名会转小写、去除末尾的点，国际化域名转为 Punycode。PSL 使用 libpsl 自带的数据，包含公共后缀及私有后缀；升级系统的 libpsl 包即可更新。域名按可注册域分组后排序，相同规则去重，并删除与最近父规则或默认出口相同的冗余规则，保留不同出口的子域例外。公共后缀（例如 `com`、`co.uk`）不能作为域名规则。

同一域名或同一组被分配不同出口、重复 YAML 键、不存在的组、非法字段和多文档 YAML 都会报错。CGI 返回 500，详情写入错误日志。相同配置语义产生稳定 PAC 和 SHA-256 ETag；支持强、弱 ETag、标签列表及 `*`。GET 返回 PAC，HEAD 只返回头部，其他方法返回 405。

生成的 PAC 使用 PSL 分组表和逐级后缀查询，使用传统 JavaScript 语法。代理方式的实际支持取决于客户端，参见 [PAC 返回值说明](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file#return_value_format)。

## 编译与运行（Ubuntu 24.04 / WSL）

```sh
sudo apt-get update
sudo apt-get install build-essential pkg-config libyaml-dev libpsl-dev libidn2-dev libssl-dev
make
make check
./pac.cgi --pac rules.yaml > proxy.pac
./pac.cgi rules.yaml                     # 查看 CGI 响应
```

可运行 `make test` 做端到端规则测试，需要 Python 3 和 Node.js，WSL 也可使用 Windows 的 `node.exe`。安装了 nginx / fcgiwrap 时，还会在临时端口验证完整 HTTP 链路，结束后停止测试进程。

在当前 Windows 工作目录进入 WSL：

```powershell
wsl -d Ubuntu-24.04 -- bash -lc 'cd /mnt/g/easypac && make check'
```

## nginx

nginx 通过 [fcgiwrap](https://github.com/gnosek/fcgiwrap) 执行 CGI，连接方式见 [nginx FastCGI 文档](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html)。

```sh
sudo apt-get install nginx fcgiwrap
sudo install -d /opt/easypac
sudo install -m 755 pac.cgi /opt/easypac/pac.cgi
sudo install -m 644 rules.yaml /opt/easypac/rules.yaml
sudo systemctl enable --now fcgiwrap.socket
```

将 [nginx.conf](nginx.conf) 中的 location 放入现有 `server` 块，确认执行用户可以读取配置、执行程序，然后运行 `sudo nginx -t && sudo systemctl reload nginx`。WSL 未启用 systemd 时，可手动运行 `sudo -u www-data fcgiwrap -f -s unix:/tmp/easypac-fcgi.socket`，并将 `fastcgi_pass` 改成 `unix:/tmp/easypac-fcgi.socket`。

```sh
curl -i http://127.0.0.1/proxy.pac
curl -i -H 'If-None-Match: "上一次响应里的标签"' http://127.0.0.1/proxy.pac
```

配置路径由 nginx 的 `PAC_RULES` 参数指定；直接运行时默认为当前目录的 `rules.yaml`，也可以作为命令行参数传入。响应使用 `Cache-Control: no-cache`，允许缓存并在再次请求时验证 ETag。
