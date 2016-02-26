# shadowsocks-go

This is a patch to shadowsocks-go, which can be used to setup a proxy inside intranet, then we can use normal shadowsocks client to access the intranet services through internet. The topological graph is like this.

```
+--------------------+
|     intranet       |
|                    |       +-------------+      +-------------+
|    +-------------+ |       | shadowsocks |      | shadowsocks |
|    | shadowsocks +---------> relay       <------+ client      |
|    | insider     | |       +-------------+      +-------------+
|    +-------------+ |
|                    |
+--------------------+
```

We add two daemon programs, shadowsocks-relay and shadowsocks-insider.

Shadowsocks-relay works like shadowsocks-server, it proxies socks connection from shadowsocks-client. But it relay data to shadowsocks-insider instead of directing data to target servers as shadowsocks-server. It listens on two ports, one for shadowsocks-client, the other for shadowsocks-insider. The port number for shadowsocks-insider is next to the one for shadowsocks-client. 

Shadowsocks-insider acts a combination of part features from shadowsocks-server and shadowsocks-client. It will proactively connect to shadowsocks-relay like shadowsocks-client conneting to shadowsocks-server. When shadowsocks-client sending sock data, shadowsocks-insider will receive the data from shadowsocks-relay through the connetion it proactively created, and then shadowsocks-insider will decode out the target server, forward data to the target server. At same time, shadowsocks-insider will initialize another connection to shadowsocks-relay, so that further request from shadowsocks-client can be processed.

**With these components, you can access the services inside intranet at the outside. But you should be cautioned the security problem incurred by this setup.

The protocol is completely compatible with the origin shadowsocks. So for shadowsocks-client, you can use any compatible shadowsocks-client.

# Install

Compiled client binaries can be download [here](http://dl.chenyufei.info/shadowsocks/). (All compiled with cgo disabled, except the mac version.)

You can also install from source (assume you have go installed):

```
# on relay
go get github.com/shadowsocks/shadowsocks-go/cmd/shadowsocks-relay
# on insider
go get github.com/shadowsocks/shadowsocks-go/cmd/shadowsocks-insider
```

It's recommended to disable cgo when compiling shadowsocks-xxx. This will prevent the go runtime from creating too many threads for dns lookup.

# Usage

Both the relay and insider program will look for `config.json` in the current directory. You can use `-c` option to specify another configuration file.

Configuration file is in json format and has the same syntax with [shadowsocks-nodejs](https://github.com/clowwindy/shadowsocks-nodejs/). You can download the sample [`config.json`](https://github.com/shadowsocks/shadowsocks-go/blob/master/config.json), change the following values:

```
server          your server ip or hostname
server_port     server port
local_port      local socks5 proxy port
method          encryption method, null by default (table), the following methods are supported:
                    aes-128-cfb, aes-192-cfb, aes-256-cfb, bf-cfb, cast5-cfb, des-cfb, rc4-md5, chacha20, salsa20, rc4, table
password        a password used to encrypt transfer
timeout         server option, in seconds
```

"server_port" specifies the port number for shadowsocks-client, the "server_port+1" will be the port number for shadowsocks-insider currently.

Run `shadowsocks-relay` on your server. To run it in the background, run `shadowsocks-server > log &`.

On insider, run `shadowsocks-insider`. Change proxy settings of your browser to

```
SOCKS5 127.0.0.1:local_port
```

## About encryption methods

AES is recommended for shadowsocks-go. [Intel AES Instruction Set](http://en.wikipedia.org/wiki/AES_instruction_set) will be used if available and can make encryption/decryption very fast. To be more specific, **`aes-128-cfb` is recommended as it is faster and [secure enough](https://www.schneier.com/blog/archives/2009/07/another_new_aes.html)**.

**rc4 and table encryption methods are deprecated because they are not secure.**

## Command line options

Command line options can override settings from configuration files. Use `-h` option to see all available options.

```
shadowsocks-insider -s server_address -p server_port -k password
    -m aes-128-cfb -c config.json
    -b local_address -l local_port
shadowsocks-relay -p server_port -k password
    -m aes-128-cfb -c config.json
    -t timeout
```

Use `-d` option to enable debug message.

## Use multiple servers on client

```
server_password    specify multiple server and password, server should be in the form of host:port
```

Here's a sample configuration [`client-multi-server.json`](https://github.com/shadowsocks/shadowsocks-go/blob/master/sample-config/client-multi-server.json). Given `server_password`, client program will ignore `server_port`, `server` and `password` options.

Servers are chosen in the order specified in the config. If a server can't be connected (connection failure), the client will try the next one. (Client will retry failed server with some probability to discover server recovery.)

## Multiple users with different passwords on server

The server can support users with different passwords. Each user will be served by a unique port. Use the following options on the server for such setup:

```
port_password   specify multiple ports and passwords to support multiple users
```

Here's a sample configuration [`server-multi-port.json`](https://github.com/shadowsocks/shadowsocks-go/blob/master/sample-config/server-multi-port.json). Given `port_password`, server program will ignore `server_port` and `password` options.

### Update port password for a running server

Edit the config file used to start the server, then send `SIGHUP` to the server process.

# Note to OpenVZ users

**Use OpenVZ VM that supports vswap**. Otherwise, the OS will incorrectly account much more memory than actually used. shadowsocks-go on OpenVZ VM with vswap takes about 3MB memory after startup. (Refer to [this issue](https://github.com/shadowsocks/shadowsocks-go/issues/3) for more details.)

If vswap is not an option and memory usage is a problem for you, try [shadowsocks-libev](https://github.com/madeye/shadowsocks-libev).
