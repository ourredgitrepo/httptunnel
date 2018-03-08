#!/usr/bin/perl
use HTTPTunnelLib;

THE_BEG:
# globals in all threads
# $LL
# $cfg
$CONFIG_FILENAME="httptunnel_server.cfg";
$template_path="sadmin";
our %loglistener : shared = ();
@globalstatus = ();

# check threads version
if (threads->VERSION<1.5) {
	print "WARNING: At least threads version 1.50 is required. Current: ".threads->VERSION."\n";
}

# do we have any command line arguments?
for (@ARGV) {
	if (m/^-[^-]/) {
		print "HTTPTunnel Server ".REL_VERSION." (c) ".REL_YEAR." Sebastian Weber <webersebastian\@yahoo.de>\n";
		print "usage: $0 [<configfile>] [--debug] [--<param>=<value> ...]\n";
		exit 1;	
	} elsif (!m/^--/) {$CONFIG_FILENAME=$_;}
}

# read the config file
$cfg=readconfig ($CONFIG_FILENAME);

# override config settings from commandline
for (@ARGV) {m/^--(.*?)(=(.*))?$/ and $cfg->{"\U$1"}=defined($2)?$3:1;}
$LL=$cfg->{LOGLEVEL};

# load some optional modules: Compress::Zlib
$cfg->{MOD_ZLIB_AVAILABLE}=eval("require Compress::Zlib");
if ($cfg->{MOD_ZLIB_AVAILABLE}) {import Compress::Zlib ':DEFAULT';$cfg->{MOD_ZLIB_LOADED}=1;}
else {push(@globalstatus,"WARNING: Module Compress::Zlib not installed. Server does not support compression.");}

# spawn logging thread
if ($LL) {
	$logqueue=Thread::Queue->new();
	$log_t=threads->create("thread_log_main");
	logline ("---------------------------------------------------------------------",1,0);
	logline ("Initializing HTTPtunnel Server",1,0);
}
# Spawn the keepalive thread
our %t_type : shared = ();
our %t_status : shared = ();
$cfg->{KEEPALIVE_ENABLE} and threads->create("keepalive_thread");

# load some optional modules: Net::LDAP, Net::MySQL, Crypt::OpenSSL::RSA, Mcrypt
$cfg->{MOD_LDAP_AVAILABLE}=eval("require Net::LDAP");
if ($cfg->{AUTH_SOURCE}==2) {
	if (!$cfg->{MOD_LDAP_AVAILABLE}) {
		push (@globalstatus,"ERROR: Module Net::LDAP could not be loaded - please install or disable HTTPTunnel LDAP authentication");
		$cfg->{AUTH_SOURCE}=0;
	} else {import Net::LDAP ':DEFAULT';}
}

$cfg->{MOD_MYSQL_AVAILABLE}=0;
if (eval("require DBI") && eval("require DBD::mysql")) {$cfg->{MOD_MYSQL_AVAILABLE}=1;}
elsif (eval("require Net::MySQL")) {$cfg->{MOD_MYSQL_AVAILABLE}=2;}
if ($cfg->{AUTH_SOURCE}==3) {
	if (!$cfg->{MOD_MYSQL_AVAILABLE}) {
		push (@globalstatus,"ERROR: Module Net::MySQL could not be loaded - please install or disable HTTPTunnel MySQL authentication");
		$cfg->{AUTH_SOURCE}=0;}
	elsif ($cfg->{MOD_MYSQL_AVAILABLE}==1) {import DBI ':DEFAULT';}
	else {import Net::MySQL ':DEFAULT';}
}

$cfg->{MOD_RSA_AVAILABLE}=eval "require Crypt::OpenSSL::RSA" && eval "require Mcrypt";
if ($cfg->{MOD_RSA_AVAILABLE}) {
	import Crypt::OpenSSL::RSA ':DEFAULT'; import Mcrypt ':DEFAULT';
	$cfg->{MOD_RSA_LOADED}=1;}
else {push(@globalstatus,"WARNING: Module Crypt::OpenSSL::RSA and/or Mcrypt not installed. Server does not support encyption.");}

# global variables
$conqueue=Thread::Queue->new();
$syncqueue=Thread::Queue->new();
$waitqueue=Thread::Queue->new();
$countqueue=Thread::Queue->new();
$restartq=Thread::Queue->new();
our $id_access : shared = "";
our $id_ban : shared = "";
our %active_connections : shared = ();

# open the server listening socket
$msg=openserverport(SERVER,$cfg->{PORT},$cfg->{IF}?inet_aton($cfg->{IF}):"") and push (@globalstatus,"Server socket on port $cfg->{PORT}: $msg");
$msg or $LL>=1 and logline ("Opening server socket on port $cfg->{PORT}");

# Spawn my worker threads
for ($i=0; $i<$cfg->{THREADS}; $i++) {threads->create("worker_thread");}

# Signal handlers
$SIG{INT}=$SIG{TERM}=$SIG{HUP}=\&tunnelexit;
$SIG{PIPE}=\&tunnelrestart;
if (@globalstatus) {for (@globalstatus) {logline($_,$LL,1);}}
if (!fileno(SERVER)) {logline ("HTTPTunnel server startup failed",$LL,1);tunnelcleanup();exit;}
logline ("HTTPtunnel server started and accepting connections",$LL,1);

# now, listen and accept connections on the server port
$rin=pack("B*", "0"x64);
vec($rin,fileno(SERVER),1)=1;
for (;;) {
	# set up the handles to listen on
	while (select ($rout=$rin,undef,undef,1)==-1) {}
	for (handles($rout)) {		# bug fixed in v1.2.1 - thanks Ron!
		if ($waitqueue->pending) {
			$conqueue->enqueue($_);
			$syncqueue->dequeue;
		} else {
			if ($cfg->{MAXTHREADS}<=0 || $countqueue->pending <= $cfg->{MAXTHREADS}) {
				threads->create("worker_thread",$_);
				$syncqueue->dequeue;
			} else {
				# refuse the connection
				$LL>=2 and logline("WARNING: Too many connections - refusing connection");
				accept(CLIENT,SERVER);
				shutdown (CLIENT,2); close (CLIENT);
			}
		}
	}
	if ($restartq->pending()) {
		tunnelcleanup ($restartq->dequeue);
		goto THE_BEG;
	}
}

# from here on, all functions are in their own thread(s)
sub keepalive_thread {
	my $iaddr   = inet_aton($cfg->{KEEPALIVE_SERVER});
	my ($fail,$ta)=(0,0);

	# Set up signal handler
	$SIG{TERM}=\&thread_exit;

	$LL>=4 and  logline ("Keepalive thread started");
	$t_type{threads->tid}="Keepalive thread";
	while (1) {
		setstatus("Sending keepalive");
		$LL>=4 and  logline("Sending keepalive");
		if (!$iaddr) {
			$LL>=1 and logline("keepalive(): no host $cfg->{KEEPALIVE_SERVER}");$fail++;}
		elsif (!socket(KALIVE, PF_INET, SOCK_STREAM, getprotobyname('tcp'))) {
			$LL>=1 and logline("keepalive(): socket() failed: reason: $!");$fail++;}
		elsif (!connect(KALIVE, sockaddr_in($cfg->{KEEPALIVE_PORT}, $iaddr))) {
			$LL>=1 and logline("keepalive(): connect() failed: reason: $!");$fail++;}
		else {$LL>=4 and logline("keepalive(): success");$fail=0;}
		fileno(KALIVE) and shutdown(KALIVE,2);close(KALIVE);
		setstatus("Idle".($fail?" - last $fail attempts failed":""));
		$ta=time+$cfg->{KEEPALIVE_INTERVAL};
		while (time<$ta) {sleep (1);}
	}
}

sub worker_thread {	# worker_thread [fileno]
	my $s_fn=shift;
	my $mode = defined($s_fn)?1:0;
	$fd="C".threads->tid;

	# Set up signal handler
	$SIG{TERM}=\&thread_exit;

	$t_type{threads->tid}=$mode?"additional server worker":"permanent server worker";
	while (1) {
		# wait for a connection to become available
		if (!$mode) {
			setstatus ("Idle");
			$waitqueue->enqueue("-");
			$s_fn=$conqueue->dequeue;
			$waitqueue->dequeue;
		}
		# accept the connection and start processing
		my $s_fd="SERVER";
		$countqueue->enqueue("-");
		accept(CLIENT,$s_fd);
		select((select(CLIENT), $|=1)[$[]); # autoflush
		my $ip = getpeername(CLIENT);
		if (length($ip)==16) {
			my ($port, $iaddr) = sockaddr_in($ip);
			$ip = inet_ntoa($iaddr);
		}
		$LL>=4 and logline ("$fd: ip trying to connect"); 
		open ($fd,"+<&CLIENT");
		close (CLIENT);
		
		# signal our main process, that the connection is accepted and he can
		# stop waiting
		$syncqueue->enqueue("x");
		if (id_isipbanned($ip)) {next;}

		setstatus ("Serving http request to $ip");
		serve_client ($ip);
	} continue {
		fileno ($fd) and shutdown($fd,2);close($fd);
		$countqueue->dequeue;
		$mode and last;
	}
	delete($t_type{threads->tid});
	delete($t_status{threads->tid});
	threads->detach();
	thread_exit();
}

sub serve_client {	# serve_client client_ip
	my $ip=shift;
	my $kamaxcount=100;
	my $kato=15;
	my $kacount=$kamaxcount;

	OUTER: while ($kacount>=0) {
		$httpka=0;
		# first, we get all the request lines

		my %h=getHTTPrequest($fd);
		if (defined($h{error})) {
			$kacount==$kamaxcount and $LL>=1 and logline ("$fd: $h{error}");
			last OUTER;}

		# here, we have a tunnel request
		if (defined($h{params}{a})) {
			# check IP
			if (!checkip(inet_aton($ip),$cfg->{SEC_IP})) {
				$LL>=1 and logline ("$fd: Unathorized access to tunnel server from $ip");
				last OUTER;}		
			# check authorisation if applicable
			my $http_user="";
			my $http_pass="";
			if (defined($h{h_authorization})) {
				($http_user,$http_pass)=split(/:/,decode_base64(substr($h{h_authorization},6)));}
			# we're only authenticating for the downstream (main) connection - the upstream connections
			# have dynamic identifiers, which should be enough security
			if ($h{params}{a} ne "s" && $cfg->{AUTH_METHOD} eq "basic") {
				my $b=checkuser($cfg->{AUTH_SOURCE},$http_user,$http_pass,$cfg->{AUTH_USER});
				if ($b) {
					mysyswrite($fd,<<EOT);
HTTP/1.1 401 Authorization Required
WWW-Authenticate: Basic realm="HTTPTunnel"
Connection: close
Content-Type: text/html

<b>Not authorized! $b</b>
EOT
					$LL>=1 and logline ("$fd: $ip authentication failure - $b"); 
					id_addaccess($ip);				
					last OUTER;}
			}
			id_delaccess($ip);
	
			if ($h{params}{a} eq "c") {
				mysyswrite($fd,"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n");
				serve_dataout($h{params}, $ip, $http_user, $http_pass); }
			elsif ($h{params}{a} eq "s") {
				defined($h{h_connection}) and $h{h_connection}=~m/^keep-alive$/i and $kacount>0 and $httpka=1;
				if ($httpka) {
					mysyswrite($fd,"HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\nKeep-Alive: timeout=$kato, max=$kacount\r\nContent-Type: text/html\r\n");
					my $resp=serve_datain($h{params}, $ip);
					mysyswrite($fd,"Content-Length: ".length($resp)."\r\n\r\n$resp");
				} else {
					mysyswrite($fd,"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n".serve_datain($h{params}, $ip));
				}
			} else {$LL>=2 and logline ("$fd: $ip force disconnect - no action defined :".$h{params}{a});}
		} else {
		# here, we have an admin request
			if (!checkip(inet_aton($ip),$cfg->{ADMIN_IP})) {
				$LL>=1 and logline ("$fd: Unathorized access to admin interface from $ip");
				last OUTER;}
			serve_admin($ip,$fd,%h);
		}
		# keep the connection alive
		$kacount--;
		if ($httpka) {
			mysyswrite($fd,"\r\n");
			my ($rin,$rout)=(pack("B*", "0"x64),"");
			vec($rin,fileno($fd),1)=1;
			for (my $i=0;$i<$kato;$i++) {
				while (select ($rout=$rin,undef,undef,1)==-1) {};
				$rout eq $rin and next OUTER;
			}
		}
		last OUTER;
	}
}

sub serve_dataout {	# serve_dataout params, user, pass
	my ($params, $ip, $http_user, $http_pass)=@_;
	my ($buf,$seq);
	my $sequence=0;
	my @sequence_buffer=();
	my $incount=0;
	my $outcount=0;
	my $sw=$params->{sw};
	$copts=$params->{o};
	my ($ka,$ki)=($cfg->{TKEEPALIVE_ENABLE},$cfg->{TKEEPALIVE_INTERVAL});
	my ($nk,$ti,$ident,$i,$s,$p,$td,$te,$symkey);
	$dad=$params->{s};
	$dpo=$params->{p};

	# we have the following global variables in this thread:
	# $fd client HTTP connection descriptor
	# $c_fd remote data or control connection (is always TCP)
	# $u_fd remote data connection (used with UDP)
	# $i_fd interprocess socket
	# $copts (1 = enable compression, 2 = enable encryption, 4 = upd, 8 = bind, 16 = bind connected)
	# $u_s, $u_p in case were cascading UDP packets
	# $dad:$dpo DST.ADDR, DST.PORT
	# $bad:$bpo BND.ADDR, BND.PORT

	# primary tunnel connect !!
	# need the following GET vars:
	# a: "c"
	# sw: Data sequence wrap number
	# s: remote server name
	# p: remote server port
	# pk: public key
	# o: connection options (1 = enable zlib compression, 4 = upd)

	$cfg->{MOD_ZLIB_LOADED} or $copts &= 254;
	$cfg->{MOD_RSA_LOADED} or $copts &= 253;

	if (!($copts & 2) && $cfg->{ENCRYPTION_FORCE}) {
			mysyswrite($fd,"c:s=ER&msg=Tunnel+server+does+not+support+unencrypted+connections\n"); return;}

	if ($copts & 2) {
		# If we're encrypting, generate a symteric key for ARCFOUR
		$td = Mcrypt->new(	algorithm => 'arcfour', mode => 'stream');
		$te = Mcrypt->new(	algorithm => 'arcfour', mode => 'stream');
		if (!$td || !$te) {
			mysyswrite($fd,"c:s=ER&msg=Could+not+initialize+Mcrypt+object\n");
			return;}
		my $iv = '';for($i = 0; $i < $td->{IV_SIZE}; $i++) {$iv .= chr(rand(256));}
		my $key = '';for($i = 0; $i < $td->{KEY_SIZE}; $i++) {$key .= chr(rand(256));}
		$td->init($key,$iv);
		$te->init($key,$iv);
		my $pkey=$params->{pk};
		$pkey=~s/(.{1,64})/$1\n/g;
		chomp $pkey;
		$pkey="-----BEGIN PUBLIC KEY-----\n$pkey\n-----END PUBLIC KEY-----";
		my $rsa_pub;
		eval {$rsa_pub = Crypt::OpenSSL::RSA->new_public_key($pkey);};
		if (!$rsa_pub) {
			mysyswrite($fd,"c:s=ER&msg=Could+not+initialize+RSA+key+-+probably+invalid+public+key+specified\n");
			return;}
		$rsa_pub->use_pkcs1_oaep_padding();
		$symkey=encode_base64(ssl_encrypt($iv.$key,$rsa_pub),'');
	}
	
	# open the interprocess socket
	$i_fd="I$fd";
	my $msg=openserverport ($i_fd,0,inet_aton("127.0.0.1"));
	if ($msg) {mysyswrite($fd,"c:s=ER&msg=".tourl("TCP $msg")."\n");return;}
    ($ident, undef) = sockaddr_in(getsockname($i_fd));

	# open the remote socket
	$c_fd="C$fd";
	$u_fd="U$fd";
	$msg=openRemote($http_user, $http_pass);
	if ($msg) {
		mysyswrite($fd,"c:s=ER&msg=".tourl("REMOTE $msg")."\n");
		killtunnel();
		return;}

    $LL>=2 and logline (($copts & 4?
    	"$fd: New tunnel established $ip sending UDP packets.":
    	($copts & 8?
    	"$fd: New tunnel established $ip listening on port $bpo.":
    	"$fd: New tunnel established $ip -> $dad:$dpo."))." Ident: ".$ident);
	if (!($copts & 12) && !$cfg->{CASCADING}) { # if we have a "normal", not cascaded connection, add it to the list
		lock %active_connections;
		$active_connections{"$dad:$dpo"}="$bad:$bpo";
	}
	mysyswrite($fd,"c:s=OK&o=$copts&i=$ident&sn=$bad&sp=$bpo".($copts & 2?"&k=".tourl($symkey):"")."\n");

	# ok, we created both sockets .. now listen on both
	$ka and $nk=time+$ki;
	$copts &= 239;
	for (;;) {
		setstatus (($copts & 4?
    	"$fd: Tunnel established $ip sending UDP packets.":
    	($copts & 8?
    	"Tunnel established $ip listening on port $bpo.":
    	"Tunnel established $ip -> $dad:$dpo."))." Ident: ".$ident."<br>Sent ".$outcount." bytes, received ".$incount." bytes");
		# were listening on all three sockets
		# - the IPC socket for incoming data
		# - the HTTP socket for a possible disconnection
		# - the remote socket for incoming data
		my $rin=pack("B*", "0"x64);
		vec($rin,fileno($i_fd),1)=1;
		vec($rin,fileno($fd),1)=1;
		fileno($c_fd) and vec($rin,fileno($c_fd),1)=1;
		fileno($u_fd) and vec($rin,fileno($u_fd),1)=1;
		$ti=time;
		while (select ($rout=$rin,undef,undef,$ka?($nk-$ti<0?0:($nk-$ti>1?1:$nk-$ti)):1)==-1) {}
		# Tunnel keepalive
		if ($ka and time>=$nk) {
			mysyswrite($fd,"\n");
			$nk=time+$ki;
			next;
		}

		for $fn (handles($rout)) {
			# HTTP socket trying to send .. do we have a HTTP disconnect?
			if ($fn == fileno($fd) && !sysread($fd,$buf,8192)) {
			    $LL>=1 and logline ("$fd: Irregular tunnel disconnect -> disconnecting server");
				$LL>=2 and logline ("$fd: Sent ".$outcount." bytes, received ".$incount." bytes");
				killtunnel();
				return;}
	
			#  IPC connecting, that means were piping the data from IPC to remote socket
			elsif ($fn == fileno($i_fd)) {
				my $ii_fd="IS$i_fd";
				accept($ii_fd,$i_fd);
				select((select($ii_fd), $|=1)[$[]); # autoflush
				my $inbuf='';
				while (sysread($ii_fd,$buf, 65536)) {$inbuf .= $buf;}
				shutdown($ii_fd,2);close($ii_fd);
				$inbuf=~s/\r//g;
				$LL>=4 and logline("$fd: Got something from IPC: $inbuf");
				for (split(/\n/,$inbuf)) {
					if ($_ eq "") {next;}
					if (m/^(\d+):(.*)$/) {
						# we have data coming in .. check the sequence and send to rserver
						# drop, if we have resent data
						$seq=$1+0;
						if ($sequence<=$seq || $sequence-$seq > $sw/2) {
							$sequence_buffer[$seq-($sequence>$seq?$sequence-$sw:$sequence)]=$2;
							$LL>=4 and logline("$fd: Got seq $seq, expected seq $sequence");
							while(defined($sequence_buffer[0]) && $sequence_buffer[0]) {
								if ($sequence_buffer[0]=~m/^c:disconnect/) {
									mysyswrite($fd,"c:disconnect on request client\n");
								    $LL>=2 and logline ("$fd: Disconnect on request client");
									$LL>=2 and logline ("$fd: Sent ".$outcount." bytes, received ".$incount." bytes");
									killtunnel();return;
								} else {
									$sequence_buffer[0]=decode_base64($sequence_buffer[0]);
									$copts & 2 and $sequence_buffer[0]=$td->decrypt($sequence_buffer[0]);
									$copts & 1 and $sequence_buffer[0]=uncompress($sequence_buffer[0]);
									$buf = shift(@sequence_buffer);
									$i=length($buf);
									if ($copts & 4) { # udp package processing
										# in case were cascading, we're forwarding the package 'as is'
										$i=$i-7-(ord(substr($buf,3,1))==1?3:ord(substr($buf,4,1)));
										if (!$cfg->{CASCADING}) {
											substr($buf,0,3)="";
											$s = ord(substr($buf,0,1,""))==1?substr($buf,0,4,""):inet_aton(substr($buf,0,ord(substr($buf,0,1,"")),""));
											$p = substr($buf,0,2,""); $p=unpack("n",$p);
										} else {$s=inet_aton($bad);$p=$bpo;}
										$s and send($u_fd, $buf, 0, sockaddr_in($p,$s));
									} else { # tcp package processing
										mysyswrite($c_fd,$buf);
									}
									$LL>=3 and logline("$fd: -> ".bin2txt(substr($buf,-$i)));
									$outcount+=$i;
									$sequence++; $sequence %= $sw;
								}
							}
						}
					} else {
						mysyswrite($fd,"l:1 Got a line I could not understand: '$_'\n");
						$ka and $nk=time+$ki;
					}
				}
				next;
			}
			
			# we got data coming in from the remote port, lets dump it to the HTTP socket
			elsif ((fileno($c_fd) && $fn == fileno($c_fd)) || (fileno($u_fd) && $fn == fileno($u_fd))) {
				if (($copts & 24) == 8) { # BIND should accept the connection
					my ($buf, $port, $ip);
					$LL>=4 and logline ("$fd: client trying to connect to bound socket");
					if ($cfg->{CASCADING} == 4) {
						($buf, $ip, $port)=get_socks4_reply($c_fd);
						if ($buf) {
							mysyswrite($fd,"c:disconnect $buf\n");
							killtunnel();return;}
					} elsif ($cfg->{CASCADING} == 5) {
						($buf, $ip, $port)=get_socks5_reply($c_fd);
						if ($buf) {
							mysyswrite($fd,"c:disconnect $buf\n");
							killtunnel();return;}
					} else {
						accept(CLIENT,$c_fd);
						select((select(CLIENT), $|=1)[$[]); # autoflush
						($port, $ip) = sockaddr_in(getpeername(CLIENT));
						$ip = inet_ntoa($ip);
						close $c_fd;
						open ($c_fd,"+<&CLIENT");
						close (CLIENT);
					}
					$LL>=4 and logline ("$fd: $ip connecting to bound socket");
					mysyswrite($fd,"b:$ip:$port\n");
					$ka and $nk=time+$ki;
					$copts|=16;
					next;
				}
	
				if (fileno($c_fd) && $fn == fileno($c_fd)) { # udp package processing
					$i=sysread($c_fd,$buf,65536);}
				else {
					$i=recv($u_fd,$buf,65536,0);}
				if (!$i) {
					mysyswrite($fd,"c:disconnect on request server\n");
				    $LL>=2 and logline ("$fd: Disconnect on request server");
					$LL>=2 and logline ("$fd: Sent ".$outcount." bytes, received ".$incount." bytes");
					killtunnel();return;
				}
				if ($copts & 4) {
					$cfg->{CASCADING} or $buf="\000\000\000\001".(sockaddr_in($i))[1].pack("n",(sockaddr_in($i))[0]).$buf;
					$i=length($buf)-10;}
				$LL>=3 and logline("$fd: <- ".bin2txt(substr($buf,-$i)));
				$incount+=$i;
				$copts & 1 and $buf=compress($buf,9);
				$copts & 2 and $buf=$te->encrypt($buf);
				mysyswrite($fd,encode_base64($buf,"")."\n");
				$ka and $nk=time+$ki;
			}
		}
	}
}

sub killtunnel {
	fileno($u_fd) and shutdown($u_fd,2);close($u_fd);
	fileno($i_fd) and shutdown($i_fd,2);close($i_fd);
	fileno($c_fd) and shutdown($c_fd,2);close($c_fd);
	if (!($copts & 12)) {
		lock %active_connections;
		delete($active_connections{"$dad:$dpo"});
	}
}

sub serve_datain {	# serve_datain params ip	# returns http response body
	my ($params, $ip)=@_;
	my ($i,$buf);
	my $ret="";
	# send data client connect
	# need the following GET vars:
	# a: "s"
	# s: sequence number
	# d: control data in the format:
	#		:<ipcname>\n<base64enc data>\n...

	my $ident='';
	my $i_fd='';

	setstatus ("Serving outbound data connection from $ip");
	$LL>=4 and logline("$fd: serve_datain()");
	for $i (split(/\n/,$params->{d})) {
		my $conerr=0;
		$i=~s/^\s*(.*?)\s*$/$1/;
		if ($i eq '') {next;}
		if ($i=~m/^>(.*)?$/) {
			# open a new IPC socket to send the next data to
			if ($ident eq $1) {next;}
			$ident = $1;
			if ($i_fd ne '') {shutdown($i_fd,2);close($i_fd);}
		    $i_fd="IC$fd";
			if (!socket($i_fd, PF_INET, SOCK_STREAM, getprotobyname('tcp'))) {
				$ret.="$ident ER TCP socket() error: $!\n";$ident=$i_fd='';next;}
			if (!connect($i_fd, sockaddr_in($ident, inet_aton("127.0.0.1")))) {
				$ret.="$ident ER TCP connect() error: $!\n";$ident=$i_fd='';next;}
		} else {
			if ($i_fd) {
				mysyswrite($i_fd,$i."\n");
				$ret.="$ident OK\n";
				$LL>=4 and logline ("$fd: Received data and sent to IPC socket: $i");
			}
		}
	}
	if ($i_fd ne '') {shutdown($i_fd,2);close($i_fd);}
	return $ret;
}

sub openRemote { # usage: openRemote user pass
	my ($http_user, $http_pass)=@_;
	my ($buf, $iaddr);
	my @a=();

	$cfg->{CASCADING} == 4 and $copts & 4 and return "UDP connections cannot be cascaded over SOCKS4";
	my $s=$cfg->{CASCADING}?$cfg->{CAS_SERVER}:$dad;
	my $p=$cfg->{CASCADING}?$cfg->{CAS_PORT}:$dpo;

	if ($copts & 4) { # upd socket
		socket($u_fd, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or return "UDP socket() failed: $!";
		bind($u_fd, sockaddr_in(0, INADDR_ANY)) or return "UDP bind() failed: $!";
		$bad="0.0.0.0";$bpo=0;
	}
	if (!$cfg->{CASCADING} && $copts & 8) { # bind and no cascading
		$iaddr   = inet_aton($dad);
		$iaddr or return "name resolution failed: reason: no host $s";
		my $b=$active_connections{"$dad:$dpo"} or return "BIND could not find primary connection";
		$bad=(split(/:/,$b))[0];
		socket($c_fd, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or return "BIND socket() failed: reason: $!";
		bind($c_fd, sockaddr_in(0, inet_aton($bad))) or return "BIND bind() failed: $!";
		listen ($c_fd,SOMAXCONN) or return "BIND listen() failed: $!";
		$bpo=(sockaddr_in(getsockname($c_fd)))[0];
	}
	if ($cfg->{CASCADING} || !($copts & 12)) { # cascading or normal connection
		$iaddr   = inet_aton($s);
		$iaddr or return "name resolution failed: reason: no host $s";
		socket($c_fd, PF_INET, SOCK_STREAM, getprotobyname('tcp')) or return "socket() failed: reason: $!";
	    connect($c_fd, sockaddr_in($p, $iaddr)) or return "connect() failed: reason: $!";
		($bpo,$bad)=sockaddr_in(getsockname($c_fd));
		$bad=inet_ntoa($bad);
	}
	fileno($c_fd) and select((select($c_fd), $|=1)[$[]); # autoflush

	my $user=$cfg->{CAS_AUTH_PASSTHROUGH}?$http_user:$cfg->{CAS_AUTH_USER};
	my $pass=$cfg->{CAS_AUTH_PASSTHROUGH}?$http_pass:$cfg->{CAS_AUTH_PASS};
	if ($cfg->{CASCADING} == 4) { # SOCKS4 connect
		# try to resolve target ip
		$iaddr   = inet_aton($dad);
		$iaddr and mysyswrite($c_fd,pack("C*", 0x04, ($copts&8?0x02:0x01), int($dpo/256), $dpo%256).$iaddr.$user.chr(0));
		$iaddr or mysyswrite($c_fd,pack("C*", 0x04, ($copts&8?0x02:0x01), int($dpo/256), $dpo%256,0,0,0,1).$user.chr(0).$dad.chr(0));
		($buf, $bad, $bpo)=get_socks4_reply($c_fd);
		$buf and return $buf;
	}
	elsif ($cfg->{CASCADING} == 5) { # SOCKS5 connect
		# send greeting
		if ($copts & 4) {	# UDP connection cascading
			($dpo, $dad) = ((sockaddr_in(getsockname($u_fd)))[0], inet_ntoa((sockaddr_in(getsockname($c_fd)))[1]));
		}
		$iaddr   = inet_aton($dad);
		mysyswrite($c_fd,pack("C*",0x05,0x02,0x00,0x02));
		mysysread($c_fd,$buf,2) or return "SOCKS5 connect failed inexpectedly";
		@a=unpack("C*",$buf);
		if ($a[1]==2) {	# authenticate
			mysyswrite($c_fd,chr(1).chr(length($user)).$user.chr(length($pass)).$pass);
			mysysread($c_fd,$buf,2) or return "SOCKS5 connect failed inexpectedly";
			@a=unpack("C*",$buf);
			$a[1] == 0 or return "SOCKS5 authentication failed";
		}
		$iaddr and mysyswrite($c_fd,pack("C*",0x05,($copts & 4)?0x03:(($copts & 8)?0x2:0x01), 0x00, 0x01).$iaddr.chr(int($dpo/256)).chr($dpo%256));
		$iaddr or  mysyswrite($c_fd,pack("C*",0x05,($copts & 4)?0x03:(($copts & 8)?0x2:0x01), 0x00, 0x03, length($dad)).$dad.chr(int($dpo/256)).chr($dpo%256));
		($buf, $bad, $bpo)=get_socks5_reply($c_fd);
		$buf and return $buf;
	}
	return "";
}

sub get_socks4_reply {	# fd
	my $c_fd=shift;
	my @a=();
	my ($buf,$bad,$bpo);

	mysysread($c_fd,$buf,8) or return "SOCKS4 connect failed inexpectedly";
	@a=unpack("C*",$buf);
	$a[1]!=0x5a and return "SOCKS4 connect rejected or failed by SOCKS server";
	$bad="$a[4].$a[5].$a[6].$a[7]";$bpo=$a[2]*256+$a[3];
	("",$bad,$bpo);
}

sub get_socks5_reply {	# fd
	my $c_fd=shift;
	my @a=();
	my ($buf,$bad,$bpo);

	mysysread($c_fd,$buf,4) or return "SOCKS5 connect failed inexpectedly";
	@a=unpack("C*",$buf);
	$a[1] == 1 and return "SOCKS5 proxy rejected connection: general failure";
	$a[1] == 2 and return "SOCKS5 proxy rejected connection: connection not allowed by ruleset";
	$a[1] == 3 and return "SOCKS5 proxy rejected connection: network unreachable";
	$a[1] == 4 and return "SOCKS5 proxy rejected connection: host unreachable";
	$a[1] == 5 and return "SOCKS5 proxy rejected connection: connection refused by destination host";
	$a[1] == 6 and return "SOCKS5 proxy rejected connection: TTL expired";
	$a[1] == 7 and return "SOCKS5 proxy rejected connection: command not supported / protocol error";
	$a[1] == 8 and return "SOCKS5 proxy rejected connection: address type not supported";
	if ($a[3]==1) {
		mysysread($c_fd,$bad,4) or return "SOCKS5 connect failed inexpectedly";
		mysysread($c_fd,$bpo,2) or return "SOCKS5 connect failed inexpectedly";
		$bad=inet_ntoa($bad);}
	elsif ($a[3]==3) {
		mysysread($c_fd,$buf,1) or return "SOCKS5 connect failed inexpectedly";
		mysysread($c_fd,$bad,ord($buf)) or return "SOCKS5 connect failed inexpectedly";
		mysysread($c_fd,$bpo,2) or return "SOCKS5 connect failed inexpectedly";}
	else {return "Got an IPv6 from remote - not supportted";}
	$bpo=unpack("n",$bpo);
	("",$bad,$bpo);
}