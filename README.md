# httpdump



### 前提条件：
* go开发环境
* Linux安装libpcap-devel库

### 构建
```
git clone https://github.com/jiangyd/httpdump.git
cd httpdump
go build httpdump.go
```

### 查看使用说明
```
$ ./httpdump --help
Usage of ./httpdump:
  -dev string
        interface example: eth0 (default "any")
  -ip string
        source ip or dst ip
  -methods string
        methods name example: GET or GET|POST
  -path string
        url request path
  -port string
        src port or dst port

```

### 例子 
```
$ sudo ./httpdump -methods "GET|POST" -port 6442 -path "/test/.*"
bpf filter: tcp port 6442 and ( tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354  )




172.16.10.244:51106->172.16.5.9:6442(tarp)

GET /test/cc HTTP/1.1
Host: 172.16.5.9:6442
User-Agent: curl/7.43.0
Accept: */*




172.16.5.9:6442(tarp)->172.16.10.244:51106

HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Tue, 20 Jul 2021 10:08:40 GMT
Content-Length: 169

{"body":"","cookies":[],"headers":{"Accept":["*/*"],"User-Agent":["curl/7.43.0"]},"method":"GET","params":[{"Key":"anypath","Value":"/cc"}],"path":"/test/cc","query":""}

```


### 问题
* 当使用-path过滤时，请求可以过滤，但是响应内容暂时无法过滤

