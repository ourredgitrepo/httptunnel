# HTTPTunnel

This is just a github-based clone of the original HTTPTunnel.

The [original documentation](https://ourredgitrepo.github.io/httptunnel/readme.html) is cloned as well.

Source: [HTTPTunnel v1.2.1](from https://sourceforge.net/projects/http-tunnel/?source=typ_redirect)

The Win32 binaries are downloaded from [here](http://neophob.com/2006/10/gnu-httptunnel-v33-windows-binaries/),
their original readme follows:

## GNU HTTPtunnel v3.3 Windows Binaries

michu October 18, 2006 24

If you cannot use a SSH client to bypass the firewall (403 error, connect command not allowed) you can use GNU httptunnel to bypass the firewall. I personally use httptunnel to bypass TRANSPARENT FIREWALLS.

As an example we forward again the Windows Remote Desktop (port 3389).

We use the same scenario as in the SSH 3 article:
There is a RemoteServer in a large company behind a Firewall. You own the MiddleServer, a public available SSH server. Last but not least there is your Workstation – you want to control the RemoteServer from this machine.

MiddleServer:

Start HTTPtunnel on MiddleServer, forward port 80 (incoming) to local SSH Port:

```
# hts --forward-port localhost:22 80
```

RemoteServer:

Start HTTPtunnel client, forward local port 900 to MiddleServer port 80 (make sure your Web Server is NOT running!):

```
# htc --forward-port 900 --proxy HTTPProxy:8080 MiddleServer:80
```

### News, 18.10.2006:

New w32 package available, change log:

* compiled with latest cygwin1.dll (v1.5.21)
* including latest cvs version
* included debug builds (for stable and cvs build)


Get the updated version: [Download GNU httptunnel Windows binaries (v3.3)r2.](http://www.neophob.com/files/httptunnel-3.3w32r2.zip)
Get the old version: [Download GNU httptunnel Windows binaries (v3.3).](http://www.neophob.com/files/httptunnel-3.3w32.zip)

As GNU httptunnel traffic is not encrypted we create a SSH tunnel in our httptunnel tunnel…:Again we use the same settings for our Putty sessin as in the SSH 3 article:

On the RemoteServer, start a SSH session to the MiddleServer. Change to the "Tunnels Tab" and enter the REMOTE forwarded port:

BUT the SSH server is of course localhost:900 (through the httptunnel).

Now start a session from your Workstation to the MiddleServer:

And now fire-up the Terminal Server Client (mstsc.exe):

Now you control the RemoteServer without change any firewall rules…

Its important that you can use only 1 httptunnel per port! Another Hint: the logging goes to the Windows application log!

IMPORTANT: httptunnel does NOT support NTLM proxy authentification!

Another example:

Server (Linux):

```
# ./hts --no-daemon -D4 --forward-port localhost:22 80
```

Client (Windows):

```
> htc --no-daemon -D4 -PPROXYSERVER:8080 -F 8888 YOUR-PUBLIC-SERVER:80
```

When you use debuglevel you might see those keep-alive messages:

```
tunnel_write_request: TUNNEL_PAD1
tunnel_read_request:  TUNNEL_PAD1
poll() timed out
tunnel_write_request: TUNNEL_PAD1
tunnel_read_request:  TUNNEL_PAD1
poll() timed out
tunnel_write_request: TUNNEL_PAD1
tunnel_read_request:  TUNNEL_PAD1
poll() timed out
```

After x seconds, the connection will close and re-establish itself:

```
tunnel_write_request: connection > 300 seconds old
tunnel_write_request: closing old connection
tunnel_out_disconnect: warning: bytes=4278 != content_length=102400
tunnel_out_disconnect: output disconnected
tunnel_out_setsockopts: non-fatal SO_SNDLOWAT error: Protocol not available
tunnel_out_setsockopts: non-fatal SO_SNDLOWAT: 0
tunnel_out_setsockopts: SO_LINGER: onoff=1 linger=2000
tunnel_out_setsockopts: non-fatal TCP_NODELAY: 1
tunnel_out_setsockopts: SO_KEEPALIVE: 1
http_write_request: POST
http://1.2.3.4:80/index.html?crap=1161192374 HTTP/1.1
tunnel_out_connect: output connected
tunnel_write_request: TUNNEL_PAD1
```

From the httport faq:

Q: When I use SSH (or VNC, or ) over GNU httptunnel, the program locks up after a few minutes (or hours). When I close the program and attempt to reconnect, SSH times out. What’s wrong?

A: Your httptunnel connection has failed on the client end (possibly due to network congestion), but the server end has not recognized that the connection has been lost and won’t allow another connection until the first connection times out. To establish a more stable tunnel, try experimenting with the various options for the htc and hts programs. The following settings seem to work pretty well for me, but your mileage may vary:

```
hts -S --max-connection-age 20000 -F localhost:22 8890
htc -F 8890 --strict-content-length -B 5k --max-connection-age 2000 -P proxy.mycompany.com:8080 10.1.1.1:8890
```

Links:

* [GNU httptunnel faq](http://www.nocrew.org/software/httptunnel/faq.html)
* [GNU httptunnel home](http://www.nocrew.org/software/httptunnel.html)
* [GNU httptunnel how-to](http://sebsauvage.net/punching/)



