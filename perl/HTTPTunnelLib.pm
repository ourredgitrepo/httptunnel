# I want to see all globals in the main script vars
package main;

use threads;
use threads::shared;
use Thread::Queue;
use Socket;
use POSIX qw(strftime);
use MIME::Base64;
use constant {
	REL_VERSION	=> "1.2.1",
	REL_YEAR	=> "2010"
};

sub bin2txt { # bin2txt data
    my @ret=@_;
    for (my $i=0;$i<=$#ret;$i++) {
		if ($LL>=4) {$ret[$i]=~s/([[:cntrl:]\x80-\xFF])/'%'.unpack("H2",$1)/ge;}
		else {$ret[$i]=~s/([[:cntrl:]\x80-\xFF])/./g;}
    }
    $#ret==0?$ret[0]:@ret;        
}

sub tohtml { # tohtml arg1 arg2 ....
    my @ret=@_;
    %convtab=("<","&lt;",">","&gt;","&","&amp;","\"","&quot;","Ä","&Auml;",
        "Ö","&Ouml;","Ü","&Uuml;","ä","&auml;","ö","&ouml;","ü","&uuml;",
        "ß","&szlig;","\n","<br>\n","\r","");
    for (my $i=0;$i<=$#ret;$i++) {
        $ret[$i]=~s/([<>&\"ÖÄÜöäüß\n\r])/defined($convtab{$1})?$convtab{$1}:$1/eg;
    }
    $#ret==0?$ret[0]:@ret;
}

sub tourl { # tourl arg1 arg2 ....
    my @ret=@_;
    for (my $i=0;$i<=$#ret;$i++) {
        $ret[$i]=~s/(\W)/'%'.unpack("H2",$1)/eg;
    }
    $#ret==0?$ret[0]:@ret;        
}

sub readconfig { # readconfig <filename>
    my $fname=shift;
    my $tmp;
    my %cfg=();
    open (FD,"<$fname") or die ("$fname: $!");
    while (<FD>) {
        chomp;
        if (m/^\s*$/) {next;}
        if (m/^#\s*(.*)$/) {next;}
        if (m/^\s*(\w+?)\s*=\s*("|)(.*?)("|)\s*$/) {
            $tmp=$1;
            $cfg{$tmp}.=((!defined($cfg{$tmp}) || $cfg{$tmp} eq "")?"":"\n").(defined($3)?$3:"");
	}	}
    close FD;
    return \%cfg;
}

sub getparams { # getparams <string> [hashref]
	my $data=shift;
	my $in=shift || {};
	$data or return $in; 
	my %h=split(/[&=]/,$data,-1);
    for my $ii (keys(%h)) {
		($in->{$ii}=$h{$ii})=~s/(\%..|\+)/$1 eq '+'?' ':pack("H2",substr($1,1))/eg;
	}
	$in;
}

sub mysyswrite {
	my ($fd,$buf)=@_;
	my ($i,$rout,$wout);
	fileno($fd) or return 0;
	while ($buf) {
		my $in=pack("B*", "0"x64);
		vec($in,fileno($fd),1)=1;
		while (select ($rout=$in,$wout=$in,undef,undef)==-1) {}
		$i=syswrite ($fd,$buf,length($buf));
		$i or last;
		$buf=substr($buf,$i);
	}
	$i;
}

sub mysysread {
	my ($fd,$buf,$len)=@_;
	my $i=0;
	$_[1]="";
	my $rin=pack("B*", "0"x64);
	vec($rin,fileno($fd),1)=1;
	while (length($_[1]) < $len) {
		# a timeout of 60 seconds should be enough in all cases
		for($i=0;$i<60;$i++) {while (select ($rout=$rin,undef,undef,1)==-1) {}  $rout eq $rin and last;}
		$i=sysread ($fd,$buf,$len-length($_[1]));
		$i or last;
		$_[1].=$buf;
	}
	$i;
}

sub openserverport { # u_openserverport fd [portnr] [listenaddr]
	my (undef,$p,$inaddr)=@_;
	socket ($_[0],PF_INET,SOCK_STREAM,getprotobyname('tcp')) or return "socket() failed: $!";
	if (!bind ($_[0], sockaddr_in($p?$p:0,$inaddr?$inaddr:INADDR_ANY))) {$p=$!; close $_[0]; return "bind() failed: $p";}
	if (!listen ($_[0],SOMAXCONN)) {$p=$!; close $_[0];return "listen() failed: $p";}
	select((select($_[0]),$|=1)[0]); # autoflush
	return "";
}

sub handles { # usage: handles <rout>
	my @h = ();
	my $i=0;
	my $s=unpack("b*",shift);

	while ($s=~m/\G(0*)1/g) {
		$i+=length($1);
		push (@h,$i++);
	}
	@h;
}

sub getline { # fd buffer line
	my $i;
	while (1) {
		if ($_[1]=~s/^(.*?)\r?\n//s) {$_[2]=$1;return 1;}
		sysread($_[0],$i,65536) or return 0;
		$_[1].=$i;
	}
}

sub getHTTPrequest { # usage: getHTTPrequest filedesc
	# first, we get all the request lines
	my $fd=shift;
	my ($i,$buf,$req)=('','','');
	my %ret=();

	my $ip = getpeername($fd);
	if (length($ip)==16) {
		my ($port, $iaddr) = sockaddr_in($ip);
		$ip = inet_ntoa($iaddr);
	}

	while (1) {
		getline ($fd,$buf,$i) or ($ret{"error"}="$ip terminated a HTTP request unexpectedly" and return %ret);
		$i eq '' and keys(%ret) and last;
		if ($i=~m§^(GET|POST) (\S*) HTTP/1§) {
			# get the GET vars
			$req=$2;
			$req=~s|/([^?]*)\??||;
			$ret{"path"}=$1;
			$ret{"params"}=getparams($req);
		}
		elsif ($i=~m/^([^:]+): (.*)$/) {
			# get headers
			$ret{"h_\L$1"}=$2;}
		$LL>=4 and logline ("$fd: Request line: $i");
	}

	# get the POST vars
	if (defined($ret{"h_content-length"})) {
		if (length($buf)<$ret{"h_content-length"}) {
			mysysread($fd,$i,$ret{"h_content-length"}-length($buf)) or ($ret{"error"}="$ip terminated a HTTP request unexpectedly" and return %ret);
			$buf.=$i;
		}
		getparams($buf,$ret{"params"});
		$LL>=4 and logline ("$fd: Request POST data: $buf");
	}
	return %ret;
}

sub getHTTPresponse { # usage: getHTTPrequest filedesc [getbody]
	# first, we get all the request lines
	my $fd=shift;
	my $gbody=shift || 0;
	my ($i,$buf)=('','');
	my %ret=();

	my $ip = getpeername($fd);
	if (length($ip)==16) {
		my ($port, $iaddr) = sockaddr_in($ip);
		$ip = inet_ntoa($iaddr);
	}

	while (1) {
		getline ($fd,$buf,$i) or ($ret{"error"}="$ip terminated a HTTP response unexpectedly" and return %ret);
		$i eq '' and keys(%ret) and last;
		if ($i=~m|^HTTP/[\d\.]+ (\d+) (.+)|) {
			if ($1 ne "200") {$ret{"error"}=$2;$ret{"errno"}=$1;}
		} elsif ($i=~m/^([^:]+): (.*)$/) {
			# get headers
			$ret{"h_\L$1"}=$2;}
		$LL>=4 and logline ("$fd: Response line: $i");
	}

	# get the Body
	if (!$gbody) {$ret{"body"}=$buf;return %ret;}
	if (defined($ret{"h_content-length"})) {
		$ret{"h_content-length"}<=length($buf) or mysysread($fd,$i,$ret{"h_content-length"}-length($buf)) or ($ret{"error"}="$ip terminated a HTTP response unexpectedly" and return %ret);
		$ret{"body"}=$buf.$i;
	} elsif (defined($ret{"h_transfer-encoding"}) && $ret{"h_transfer-encoding"} eq "chunked") {
		my ($bbuf,$tmp)=('','');
		# get all data chunks
		while(1) {
			getline ($fd,$buf,$i) or ($ret{"error"}="$ip terminated a HTTP response unexpectedly" and return %ret);
			$LL>=4 and logline ("$fd: Response body line: $i");
			$i=~s/;.*$//; # strip chunk extensions
			$i=~s/[^0-9A-Fa-f]//g; # strip all invalid characters
			$i=hex $i or last;
			$bbuf.=substr($buf,0,$i,"");
			if (length($bbuf)<$i) {
				mysysread($fd,$tmp,$i-length($bbuf)) or ($ret{"error"}="$ip terminated a HTTP response unexpectedly" and return %ret);
				$bbuf.=$tmp;}
			getline ($fd,$buf,$i);
		}
		# get trailer
		while (1) {
			getline ($fd,$buf,$i) or return %ret;
			$LL>=4 and logline ("$fd: Response trailer line: $i");
			$i eq '' and last;
			$i=~m/^([^:]+): (.*)$/ and $ret{"h_\L$1"}=$2;
		}
		$ret{body}=$bbuf;
	} else {
		$ret{"body"}=$buf;
		while (sysread($fd,$buf,65536)) {$ret{"body"}.=$buf;}
	}
	$LL>=4 and logline ("$fd: Response body: $ret{body}");
	return %ret;
}

sub load_template {
# --------------------------------------------------------
# Loads and parses a template. Expects to find as input a
# template file name, and a hash ref and optionally template text.
# If text is defined, then no file is loaded, but rather the template
# is taken from $text.
#
    my $__i;
    my ($__tpl, $__vars, $__string) = @_;
    my $__parsed="";
    my $__begin="<%";
    my $__end="%>";
    my $__expr;

    if (!defined($template_path)) {$template_path="templates";}
    if (!defined $__string) {
        if (!open (FH, "<$template_path/$__tpl")) {
            $__parsed="Could not load $__tpl : $!\n";
            return $__parsed;                                                         
        }
        $__string=join('',<FH>);
        close FH;
    }
     
    # setup local variable space
    foreach (keys %$__vars) {$__i=$_;$$__i = $__vars->{$__i};}
    my @__stack=();
    my @__lines = split /\n/, $__string;
    my $__skip = 0;
    my $__skippingloop = 0;
    
    # main loop
    
    for ($__i=0;$__i<=$#__lines;$__i++){
        $_=$__lines[$__i];

        # Skip comments and blank lines
        /^#/ and next;

        # <%end%>
        if (/$__begin\s*end\s*$__end/o) {
            if ($__skip) {               
                if (!$__skippingloop || $__stack[0]!=-1 || $__skip!=1) {$__skip--;}
                $__skip or $__skippingloop=0;
                shift @__stack;
            } else {           
                $__stack[0]!=-1?($__i=$__stack[0]):(shift @__stack);
            }                                                       
            next;
        }
         
        # <%if EXPR%>
        if (m/$__begin\s*if\s*(.+)?\s*$__end/o) {
					$__expr = $1;
            if ($__skip || !eval $__expr) {$__skip++;}
            unshift (@__stack,"-1");                  
            next;
        }
         
        # <%loop%>
        if (m/$__begin\s*loop\s*$__end/o) {
            $__skip and $__skip++;         
            unshift (@__stack,$__i);       
            next;
        }
         
        $__skip and next;
        # <%break%>
        if (m/$__begin\s*break\s*$__end/o) {
            $__skip or $__skip++;           
            $__skippingloop=1;              
            next;
        }
         
        # <%cont%>
        if (m/$__begin\s*cont\s*$__end/o) {
            while ($__stack[0]==-1) {shift @__stack;}
            $__i=$__stack[0];
            next;
        }
         
        # <%include FNAME%>
        if (/$__begin\s*include\s*(.+)?\s*$__end/o) {
            my $__fnam=$1;                           
            while ($__fnam=~/^\$/) {$__fnam=eval $__fnam;}
            $_=load_template ($__fnam,$__vars);
            $__parsed .= $_ . "\n";            
            next;
        }
         
        # <%exit%>
        if (m/$__begin\s*exit\s*$__end/o) {
            last;
        }
         
        # <%eval EXPR%>
        if (m/$__begin\s*eval\s*(.+)?\s*$__end/o) {
            $__expr = $1;                       
            eval $__expr;                          
            next;
        }
         
        # <%EXPR%>
        s/$__begin\s*(.+?)\s*$__end/defined(eval $1)?eval $1:""/goe;
         
        $__parsed .= $_ . "\n";
    }
    return $__parsed;
}

sub checkip {	# checkip ip ips
	my ($ip,$ips)=@_;
	if (!defined($ips) || $ips!~m/\d/) {return 1;}
	for (split(/,/,$ips,-1)) {
		$_ or return 1;
		@a=split('/',$_);
		$a[1] or $a[1]=32;
		my ($l1,$l2)=(unpack("N",$ip),unpack("N",inet_aton($a[0])));
		my $nl=unpack("N", pack("B32", ('1' x $a[1]).('0' x (32-$a[1]))));
		($l1&$nl)==($l2&$nl) and return 1;
	}
	return 0;
}	

sub thread_exit {
	threads->exit(0);
}

sub thread_log_main {	# thread_log_main -- needs utilsconfigure ("cfg",...) (logqueue,...)
	my $line;
	# Open Logfile
	open (LOG, ">>$cfg->{LOGFILE}") or die "open $cfg->{LOGFILE}: $!";
	select ((select(LOG),$|=1)[0]); # autoflush
	while (1) {
		# cycle Logfile
		if (tell(LOG)>$cfg->{MAXLOGSIZE}) {
			my $msg = "Logfile reached maximum size ($cfg->{MAXLOGSIZE}) - rotating\r\n";
			$cfg->{DEBUG} and print $msg; print LOG localtime()." - ".$msg;
			close (LOG);
			cyclelog($cfg->{LOGFILE});
			open (LOG, ">$cfg->{LOGFILE}") or $LL=0;
			$LL and select ((select(LOG),$|=1)[0]); # autoflush
			$msg="Opening new Logfile\r\n";
			$cfg->{DEBUG} and print $msg; print LOG localtime()." - ".$msg;
		}
		$line=$logqueue->dequeue;
		if ($line eq "x") {close(LOG);last;}
		print LOG $line."\r\n";
		# send line to all registered listeners
		for (keys(%loglistener)) {$loglistener{$_}->enqueue($line."\r\n");}
	}
}

sub cyclelog {
	my $ln=shift;
	my $buf;
	
	# calculate new name
	my $ts=strftime("%Y%m%d.%H%M%S",localtime);
	my $nn="$ln.$ts";
	$ln=~m/^(.*?)\.(...)$/ and $nn="$1.$ts.$2";
	
	# pack file
	if ($cfg->{MOD_ZLIB_LOADED}) {
		$nn.=".gz";
		open (LOG, "<$ln") or die "cyclelog(): open $ln: $!";
		my $gz = gzopen($nn, "wb9") or die "cyclelog(): Cannot open $nn: $gzerrno\n" ;
		$gz->gzwrite($buf) while read(LOG,$buf,4096);
		$gz->gzclose();
		close LOG;
		unlink $ln;
	} else {
		rename $ln, $nn;
	}

	# clean up old log files
	if ($cfg->{MAXLOGS} ne "") {
		$nn=~s/$ts/*/;
		my $i=0;
		for (sort {$b cmp $a} glob($nn)) {++$i>$cfg->{MAXLOGS} and unlink $_;}
	}
}

sub logline {	# logline cfghashref message [log] [console]
	my ($msg,$l,$c)=@_;
	defined($l) or $l=1;
	defined($c) or $c=$cfg->{DEBUG};
	$l and $logqueue->enqueue(localtime()." - ".$msg);
	$c and print $msg."\n";
}

sub setstatus {
	$t_status{threads->tid}=shift;
}

sub checkuser {	#usage: c_checkuser method, uname, pass, [userlist for method=1]
	my ($method,$user,$pass,$ulist) = @_;
	if ($method==0) {	# no authentication
		return "";
		
	} elsif ($method==1) {	# fixed list authentication
		$ulist=~/^$user:$pass$/m and return "";
		
	} elsif ($method==2) {	# ldap authentication
		my $ldap = Net::LDAP->new( $cfg->{LDAP_SERVER}.":".($cfg->{LDAP_PORT}?$cfg->{LDAP_PORT}:"389")) or return "LDAP: $@";
		my $mesg = $ldap->bind( $cfg->{LDAP_USER}?($cfg->{LDAP_USER}, password => $cfg->{LDAP_PASS}):());
		my $f = $cfg->{LDAP_FILTER};
		$f=~s/\\u/$user/g;
		$f=~s/\\p/$pass/g;
		$mesg = $ldap->search(
                        base   => $cfg->{LDAP_BASE},
                        filter => $f
                      );
        $mesg->code and return "LDAP: ".$mesg->error;
        $ldap->unbind;
        $mesg->entries>0 and return "";	
	} elsif ($method==3) {	# mysql authentication
		my $q = $cfg->{MYSQL_QUERY};
		$q=~s/\\u/$user/g;
		$q=~s/\\p/$pass/g;
		if ($cfg->{MOD_MYSQL_AVAILABLE} == 2) {
			my $mysql;
			eval {$mysql = Net::MySQL->new(
				hostname => $cfg->{MYSQL_SERVER},
				port     => $cfg->{MYSQL_PORT}?$cfg->{MYSQL_PORT}:"3306",
				database => $cfg->{MYSQL_DB},
				user     => $cfg->{MYSQL_USER},
				password => $cfg->{MYSQL_PASS});};
			!$mysql and return "MySQL new $!";
			$mysql->is_error and return "MYSQL connect: ".$mysql->get_error_message;
			$mysql->query($q);
			$mysql->is_error and return "MYSQL query: ".$mysql->get_error_message;
			my $i=$mysql->has_selected_record;
			$mysql->close;
			$i and return "";
		} else {
			my $dbh = DBI->connect ("DBI:mysql:database=$cfg->{MYSQL_DB};host=$cfg->{MYSQL_SERVER};port=".($cfg->{MYSQL_PORT}?$cfg->{MYSQL_PORT}:"3306"), $cfg->{MYSQL_USER}, $cfg->{MYSQL_PASS});
			!$dbh and return "DBI::connect error $!";
			$dbh->{'mysql_errno'} and return "DBI::connect ".$dbh->{'mysql_error'};
			my $sth = $dbh->prepare($q);
			!$sth and return "DBI::prepare $!";
			$dbh->{'mysql_errno'} and return "DBI::prepare ".$dbh->{'mysql_error'};
			$sth->execute();
			$dbh->{'mysql_errno'} and return "DBI::execute ".$dbh->{'mysql_error'};
			my $i=$sth->fetchrow_arrayref;
			$sth->finish();
			$dbh->disconnect();
			$i and return "";
		}
	}
	return "not authorized";
}

sub serve_log { # c_servelog paramhash, fd
	my ($h,$c_fd)=@_;
	my $size=defined($h->{size})?$h->{size}:65536;
	my ($buf);
	
	# dump out last $size bytes of the logfile
	open (LOG, "<$cfg->{LOGFILE}") or return "ERROR: Cannot open file $cfg->{LOGFILE}";
	my @arr=stat(LOG);
	seek(LOG,$arr[7]<$size?0:$arr[7]-$size,0);
	while(<LOG>) {if (!mysyswrite($c_fd,tohtml($_))) {close LOG;return;}}
	mysyswrite($c_fd,"<script>s();</script>");
	close LOG;

	# now, create a shared queue and register it as a loglistener
	{
		lock (%loglistener);
		$loglistener{threads->tid}=Thread::Queue->new();
	}

	LOGMAIN: while (1) {
		my $rin=pack("B*", "0"x64);
		vec($rin,fileno($c_fd),1)=1;
		while (select ($rout=$rin,undef,undef,0.5)==-1) {}
		handles($rout) and last LOGMAIN;
		while ($buf=$loglistener{threads->tid}->dequeue_nb) {mysyswrite($c_fd,tohtml($buf)."<script>s();</script>") or last LOGMAIN;}
	}
	{
		lock (%loglistener);
		delete ($loglistener{threads->tid});
	}		
	return "";
}

sub serve_admin {	# serve_admin iaddr,fd,paramhash

	my ($ip,$c_fd,%h)=@_;
	my (@a,$buf);
	
	# check authorisation if applicable
	if ($cfg->{ADMIN_AUTH_USER} && (!defined($h{"h_authorization"}) || $h{"h_authorization"} ne "Basic ".encode_base64($cfg->{ADMIN_AUTH_USER}.":".$cfg->{ADMIN_AUTH_PASS},''))) {
		mysyswrite($c_fd,<<EOT);
HTTP/1.1 401 Authorization Required
WWW-Authenticate: Basic realm="HTTPTunnel Admin"
Connection: close
Content-Type: text/html

<b>Not authorized!</b>
EOT
		id_addaccess($ip);
		return;
	}
	id_delaccess($ip);

	$h{path}=~s/\.\.//;
	$h{path} or $h{path}="admin.tpl";
	
	# get mime type
	my %mime=(
		tpl => "text/html",
		html => "text/html",
		css => "text/css",
		gif => "image/gif",
		jpg => "image/jpeg",
		png => "image/png",
		js => "application/x-javascript");
	my $mimetype="text/html";
	$h{path}=~m/\.([^\.]+)$/ and defined($mime{$1}) and $mimetype=$mime{$1};
	
	# print out file
	mysyswrite($c_fd,<<EOT);
HTTP/1.1 200 OK
Connection: close
Content-Type: $mimetype

EOT
	if ($h{path}=~m/\.tpl$/) {
		mysyswrite($c_fd,load_template($h{path},{type => \%t_type, status => \%t_status, params => $h{params}}));
	} else {
		open (FH,"<","$template_path/".$h{path}) or open (FH,"<","common/".$h{path});
		if (!fileno(FH)) {
			mysyswrite($c_fd, "Not found: ".$h{path});
		} else {
			while (sysread(FH,$buf,65536)) {mysyswrite($c_fd,$buf);}
			close FH;
		}
	}
	if (defined($h{params}{d_action}) && $h{params}{d_action} eq "save") {
		fileno $c_fd and shutdown($c_fd,2);close $c_fd;
		save_config($h{params});
	}
	if ($h{path}=~m/log\.tpl$/) {
		mysyswrite($c_fd, serve_log($h{params},$c_fd));
	}	
}

sub save_config { # saveConfig paramhash
	my $h=shift;
	my $i;
	# save config
	open(FH,">",$CONFIG_FILENAME);

	for (sort(keys(%$h))) {
		m/^[A-Z][_A-Z]+$/ or next;
		if ($h->{$_} eq "") {print FH "$_ = \n";}
		else {
			for my $i (split(/\n/,$h->{$_},-1)) {
				$i=~s/\r//gs;
				$i eq "" and next;
				print FH "$_ = $i\n";
			}
		}
	}
	close FH;
	
	# restart client
	$restartq->enqueue("Config changed by admin - Restarting ...");
}

sub tunnelrestart {
	$restartq->enqueue("Caught SIG$_[0] - Restarting ...");
}

sub tunnelexit {
	tunnelcleanup (($_[0]?"Caught SIG$_[0] - ":"")."Shutting down");
	exit (0);
}

sub tunnelcleanup {
	my ($i,$fd);
	defined ($_[0]) and logline ($_[0],$LL,1);
	# clean up the logger thread
	if ($LL) {
		$logqueue->enqueue("x");
		$log_t->join;
	}
	# clean up all other threads
	foreach $i (threads->list()) {$i->kill("TERM");}
	foreach $i (threads->list()) {defined ($sendqueue) and $sendqueue->enqueue("x");$conqueue->enqueue("x");}
	# shut down all server sockets
	if (%server_sockets) {
		for $i (keys(%server_sockets)) {
			$fd=$server_sockets{$i}->{fd};
			fileno($fd) and shutdown($fd,2);close($fd);
		}
	}
	fileno(SERVER) and shutdown(SERVER,2);close (SERVER);
	foreach $i (threads->list()) {$i->join();}
}

sub ssl_encrypt {
	my ($source,$key)=@_;
	my $maxlength=$key->size()-42;
	my $output='';
	while($source){$output.=$key->encrypt(substr($source,0,$maxlength,''));}
	return $output;
}

sub ssl_decrypt {
	my ($source,$key)=@_;
	my $maxlength=$key->size;
	my $output='';
	while($source){$output.=$key->decrypt(substr($source,0,$maxlength,''));}
	return $output;
}

# intrusion detection functions
sub id_addaccess { # ip
	$cfg->{ID_ENABLE} or return;
	my $ip=shift;
	#expire accesses
	my $ct=time()-$cfg->{ID_TIMEOUT};
	lock $id_access;
	$id_access=~s/(=(\d+))/$2<$ct?'':$1/eg;
	$id_access=~s/&([\.\d]+)(?=(&|$))//g;
	#add access
	$ct=time();
	if ($id_access=~/&$ip=/) {
		$id_access=~s/&$ip=/&$ip=$ct=/;
	} else {
		$id_access.="&$ip=$ct";}
	#move the accessing client to the banlist if applicable
	if ($id_access=~s/&($ip)(=\d+){$cfg->{ID_MAXACCESS}}(=\d+)*//) {
		lock $id_ban;
		$id_ban.="&$ip=$ct";
		$LL and logline ("SECURITY WARNING: banning $ip for $cfg->{ID_TIMEOUT} seconds");
	}
}

sub id_delaccess {
	$cfg->{ID_ENABLE} or return;
	my $ip=shift;
	lock $id_access;
	$id_access=~s/&$ip(=\d+)*//;
	lock $id_ban;
	$id_ban=~s/&$ip(=\d+)*//;
}

my $id_lastexpire : shared = 0;
sub id_isipbanned {
	$cfg->{ID_ENABLE} or return 0;
	my $ip=shift;
	#expire banlist (at most every 5 seconds)
	if (time()>$id_lastexpire+5) {
		lock $id_ban;
		lock $id_lastexpire;
		$id_lastexpire=time();
		my $ct=$id_lastexpire-$cfg->{ID_BANTIMEOUT};
		$id_ban=~s/(&.+?=(\d+))/$2<$ct?'':$1/eg;
	}
	$id_ban=~/&$ip=/ and return 1;
	return 0;
}
1;
