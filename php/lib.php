<?php

// check version - we need PHP5 !
if (version_compare("5.0.0",phpversion())==1) die ("Only PHP 5 or above supported");

// get basic username and password
if (!$_SERVER['PHP_AUTH_USER'] && $_SERVER["REDIRECT_HTTP_AUTHORIZATION"]) {
	list($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']) =
		explode(':' , base64_decode(substr($_SERVER["REDIRECT_HTTP_AUTHORIZATION"],6)));
}

// set up error handling
error_reporting(E_ALL);
set_error_handler("myErrorHandler");

// set up intrusion detection
$id_fname="id_stats.php";
$id_lock="id_lock.php";
if ($ID_ENABLE && !file_exists($id_fname)) {file_put_contents($id_fname," \n ");}
if (id_isipbanned($_SERVER["REMOTE_ADDR"])) die("banned");

// error handler function
function myErrorHandler($errno, $errstr, $errfile, $errline) {
	switch ($errno) {
	case E_ERROR:
		$errfile=preg_replace('|^.*[\\\\/]|','',$errfile);
		echo "l:1 ERROR in line $errline of file $errfile: [$errno] $errstr\n";
		exit;
	}
}	

function logline ($ll,$msg) {
	global $LOGLEVEL, $LOG, $MAXLOGSIZE, $LOGFILE;
	if ($LOGLEVEL and $ll<=$LOGLEVEL) {
		$LOG=fopen ($LOGFILE, "a");
		if ($LOG) {
			fwrite ($LOG, date("d.m.Y H:i:s")." - $msg\r\n");
			$lstat=fstat($LOG);
			if ($lstat["size"]>$MAXLOGSIZE) rotatelog();
			fclose($LOG);
		}
	}
}

function rotatelog() {
	global $MAXLOGSIZE, $LOGFILE, $LOG, $LOGLEVEL,$logrtry;
	fwrite ($LOG, date("d.m.Y H:i:s")." - Logfile reached maximum size ($MAXLOGSIZE)- rotating.\r\n");
	fclose ($LOG);
	rename ($LOGFILE,"$LOGFILE.old");
	$LOG=fopen ($LOGFILE, "a");
	if (!$LOG) $LOGLEVEL=0;
	else fwrite ($LOG, date("d.m.Y H:i:s")." - Opening new Logfile.\r\n");
}

function checkip ($ip,$ips) {
	if (!$ips) return true;
	foreach (preg_split('/,/',$ips) as $i) {
		$a=preg_split("'/'",$i);
		if (!isset($a[1]) || $a[1]==0) $a[1]=32;
		$l1=ip2long($a[0]);
		$l2=ip2long($ip);
		$nl=bindec(str_repeat('1',$a[1]).str_repeat('0',32-$a[1]));
		if (($l1&$nl)==($l2&$nl)) return true;
	}
	return false;
}

function rep_cb ($m) {return "%".str_pad(dechex(ord($m[0])),2,0,STR_PAD_LEFT);}

function bin2txt ($ret) {
	global $LOGLEVEL;
	if ($LOGLEVEL>=4)
		return preg_replace_callback('/[[:cntrl:]\x80-\xFF]/','rep_cb',$ret);
	else
		return preg_replace('/([[:cntrl:]\x80-\xFF])/','.',$ret);
}

function ssl_encrypt($source,$key){
	$maxlength=128-42;	// keylength minus padding constant for pkcs1_oaep
	$output='';
	while($source) {
		$input=substr($source,0,$maxlength);
		$source=substr($source,$maxlength);
		$ok= openssl_public_encrypt($input,$encrypted,$key,OPENSSL_PKCS1_OAEP_PADDING);
		$output.=$encrypted;
	}
	return $output;
}

# intrusion detection functions
function id_lock() {
	global $id_lock,$_lock_fd;
	$_lock_fd=fopen($id_lock,"w+");
	while (!flock($_lock_fd, LOCK_EX)) {}
}

function id_unlock() {
	global $_lock_fd;
	flock($_lock_fd, LOCK_UN);
	fclose($_lock_fd);
}

function id_addaccess ($ip) {
	global $ID_ENABLE,$ID_MAXACCESS,$ID_TIMEOUT,$id_fname,$_ct,$id_access,$id_ban;
	if (!$ID_ENABLE) return;
	//expire accesses
	$_ct=time()-$ID_TIMEOUT;
	$id_access=preg_replace_callback('/(=(\d+))/',create_function('$m','global $_ct;return($m[2]<$_ct?"":$m[1]);'),$id_access);
	$id_access=preg_replace('/&([\.\d]+)(?=(&|$))/','',$id_access);
	//add access
	$_ct=time();
	if (preg_match("/&$ip=/",$id_access)) $id_access=preg_replace("/&$ip=/","&$ip=$_ct=",$id_access);
	else $id_access.="&$ip=$_ct";

	//move the accessing client to the banlist if applicable
	$count=0;
	$tmp=preg_replace('/&'.$ip.'(=\d+){'.$ID_MAXACCESS.'}(=\\d+)*/',"",$id_access,-1);
	if ($tmp!=$id_access) {
		$id_access=$tmp;
		$id_ban.="&$ip=$_ct";
		logline (1,"SECURITY WARNING: banning $ip for $ID_TIMEOUT seconds");}
	//write data
	file_put_contents($id_fname,"$id_access \n$id_ban ");
	id_unlock();
}

function id_delaccess ($ip) {
	global $ID_ENABLE,$id_fname,$id_access,$id_ban;
	if (!$ID_ENABLE) return;
	//delete from lists
	$id_access=preg_replace("/&$ip(=\\d+)*/","",$id_access);
	$id_ban=preg_replace("/&$ip(=\\d+)*/","",$id_ban);
	//write data
	file_put_contents($id_fname,"$id_access \n$id_ban ");
	id_unlock();
}

function id_isipbanned ($ip) {
	global $ID_BANTIMEOUT,$ID_ENABLE,$id_access,$id_ban,$id_fname,$_ct;
	if (!$ID_ENABLE) return(0);
	//read in data
	id_lock();
	$f=file($id_fname);
	$id_access=rtrim($f[0]);
	$id_ban=rtrim($f[1]);
	//expire banlist
	$_ct=time()-$ID_BANTIMEOUT;
	$id_ban=preg_replace_callback('/(&.+?=(\d+))/',create_function('$m','global $_ct;return($m[2]<$_ct?"":$m[1]);'),$id_ban);
	//check banlist
	return (preg_match("/&$ip=/",$id_ban));
}

function shutdown () {
	global $ipsock, $rmsock, $outcount, $incount, $td, $te, $sockname, $useunix;

	if (connection_status() & 1) { # ABORTED
		logline (1, $_SERVER["REMOTE_ADDR"].": Irregular tunnel disconnect -> disconnecting server");
		logline (2, $_SERVER["REMOTE_ADDR"].": Sent ".$outcount." bytes, received ".$incount." bytes");
	} elseif (connection_status() & 2) { # TIMEOUT
		logline (1, $_SERVER["REMOTE_ADDR"].": PHP script timeout -> disconnecting server");
		logline (2, $_SERVER["REMOTE_ADDR"].": Sent ".$outcount." bytes, received ".$incount." bytes");
	}
	
	if (isset($td)) {mcrypt_generic_deinit($td);mcrypt_module_close($td);}
	if (isset($te)) {mcrypt_generic_deinit($te);mcrypt_module_close($te);}
	if ($ipsock) fclose($ipsock);
	if ($rmsock) fclose($rmsock);
	if ($_REQUEST["a"]=="c" && $useunix && $sockname && file_exists($sockname)) {unlink ($sockname);}
}

function get_socks4_reply ($fd) {
	$buf=fread($fd,8); if (empty($buf)) return array("SOCKS54 connect failed inexpectedly");
	$a=unpack("C*",$buf);
	if ($a[2]!=0x5a) return array("SOCKS4 connect rejected or failed by SOCKS server");
	return array("","$a[5].$a[6].$a[7].$a[8]",$a[3]*256+$a[4]);
}

function get_socks5_reply ($fd) {
	$msg="SOCKS5 connect failed inexpectedly";
	$buf=fread($fd,4); if (empty($buf)) return array($msg);
	$a=unpack("C*",$buf);
	if ($a[2] == 1) return array("SOCKS5 proxy rejected connection: general failure");
	if ($a[2] == 2) return array("SOCKS5 proxy rejected connection: connection not allowed by ruleset");
	if ($a[2] == 3) return array("SOCKS5 proxy rejected connection: network unreachable");
	if ($a[2] == 4) return array("SOCKS5 proxy rejected connection: host unreachable");
	if ($a[2] == 5) return array("SOCKS5 proxy rejected connection: connection refused by destination host");
	if ($a[2] == 6) return array("SOCKS5 proxy rejected connection: TTL expired");
	if ($a[2] == 7) return array("SOCKS5 proxy rejected connection: command not supported / protocol error");
	if ($a[2] == 8) return array("SOCKS5 proxy rejected connection: address type not supported");

	if ($a[4]==1) {
		$bad=fread($fd,4); if (empty($bad)) return array($msg);
		$bpo=fread($fd,2); if (empty($bpo)) return array($msg);
	} elseif ($a[4]==2) {
		$buf=fread($fd,1); if (empty($buf)) return array($msg);
		$bad=fread($fd,ord($buf)); if (empty($bad)) return array($msg);
		$bpo=fread($fd,2); if (empty($bpo)) return array($msg);
	} else {
		return array("Got an IPv6 from remote - not supportted");}
	$arr=unpack("N",$bad);
	$bad=long2ip($arr[1]);
	$arr=unpack("n",$bpo);
	$bpo=$arr[1];
	return array("",$bad,$bpo);
}

function openRemote ($http_user, $http_pass) {
	global $copts,$dad,$dpo,$bad,$bpo,$CASCADING, $CAS_SERVER, $CAS_PORT, $CAS_AUTH_PASSTHROUGH, $CAS_AUTH_USER, $CAS_AUTH_PASS, $usock, $rmsock, $ident;
	
	if ($CASCADING == 4 && $copts & 4) return "UDP connections cannot be cascaded over SOCKS4";
	$s=$CASCADING?$CAS_SERVER:$dad;
	$p=$CASCADING?$CAS_PORT:$dpo;
	if ($copts & 4) { // udp socket
		$usock = stream_socket_server("udp://0.0.0.0:0", $errno, $errstr, STREAM_SERVER_BIND);
		if (!$usock) return "UDP stream_socket_server() failed: reason: $errstr";	
		$bad="0.0.0.0";$bpo=0;
	}
	if (!$CASCADING && $copts & 8) { // bind and no cascading
		$bad = getmyip(true);
		$rmsock = stream_socket_server("tcp://0.0.0.0:0", $errno, $errstr);
		if (!$rmsock) return "BIND stream_socket_server() failed: reason: $errstr";
		$bpo=preg_replace('/^.*?:/','',stream_socket_get_name($rmsock,false));
		logline (4,"$ident: opened BIND server on $bad:$bpo");
	}
	if ($CASCADING || !($copts & 12)) { // tcp socket
		$rmsock = stream_socket_client("tcp://$s:$p", $errno, $errstr);
		if (!$rmsock) return "TCP stream_socket_client(tcp://$s:$p) failed: reason: $errstr";
		$bad=preg_replace('/:.*$/','',stream_socket_get_name($rmsock,false));
		$bpo=preg_replace('/^.*?:/','',stream_socket_get_name($rmsock,false));
		stream_set_blocking($rmsock,1);
	}

	$user=$CAS_AUTH_PASSTHROUGH?$http_user:$CAS_AUTH_USER;
	$pass=$CAS_AUTH_PASSTHROUGH?$http_pass:$CAS_AUTH_PASS;
	if ($CASCADING == 4) { # SOCKS4 connect
		$iaddr   = ip2long(gethostbyname($dad));
		# try to resolve target ip
		if ($iaddr) myfwrite($rmsock,pack("CCCCN",0x04, ($copts&8?0x02:0x01), floor($dpo/256), $dpo%256, $iaddr).$user.chr(0));
		else myfwrite($rmsock,pack("C*",0x04, ($copts&8?0x02:0x01), floor($dpo/256), $dpo%256, 0, 0, 0, 1).$user.chr(0).$server.chr(0));
		$a=get_socks4_reply($rmsock);
		if ($a[0]) return $a[0];
		$bad=$a[1];$bpo=$a[2];
	}
	elseif ($CASCADING == 5) { # SOCKS5 connect
		if ($copts & 4) {	# UDP connection cascading
			$dpo=preg_replace('/^.*?:/','',stream_socket_get_name($usock,false));
			$dad=preg_replace('/:.*$/','',stream_socket_get_name($rmsock,false));
		}
		# send greeting
		myfwrite($rmsock,pack("C*",0x05,0x02,0x00,0x02));
		$buf=fread($rmsock,2); if (empty($buf)) return $msg;
		$a=unpack("C*",$buf);
		if ($a[2]==2) {	# authenticate
			myfwrite($rmsock,chr(1).chr(strlen($user)).$user.chr(strlen($pass)).$pass);
			$buf=fread($rmsock,2); if (empty($buf)) return $msg;
			$a=unpack("C*",$buf);
			if ($a[2] != 0) return "SOCKS5 authentication failed";
		}
		$iaddr   = ip2long(gethostbyname($dad));
		if ($iaddr) $buf=pack("CCCCNCC",0x05,($copts & 4)?0x03:(($copts & 8)?0x2:0x01), 0x00, 0x01, $iaddr, floor($dpo/256), $dpo%256);
		else $buf=pack("C*",0x05,($copts & 4)?0x03:(($copts & 8)?0x2:0x01), 0x00, 0x03, strlen($dad)).$dad.chr(floor($dpo/256)).chr($dpo%256);
		myfwrite($rmsock,$buf);
		$a=get_socks5_reply($rmsock);
		if ($a[0]) return $a[0];
		$bad=$a[1];$bpo=$a[2];
	}
	return "";
}

function checkuser ($user,$pass) {
	global $AUTH_METHOD, $AUTH_USER, $AUTH_SOURCE, $LDAP_SERVER, $LDAP_PORT, $LDAP_USER, $LDAP_PASS, $LDAP_FILTER, $LDAP_BASE, $LDAP_SCOPE, $MYSQL_SERVER, $MYSQL_PORT, $MYSQL_USER, $MYSQL_PASS, $MYSQL_DB, $MYSQL_QUERY;
	if ($AUTH_METHOD != "basic") {	# no authentication
		return "";
		
	} elseif ($AUTH_SOURCE==1) {	# fixed list authentication
		if (preg_match('/^'.$user.':'.$pass.'$/m',$AUTH_USER)) return "";
		
	} elseif ($AUTH_SOURCE==2) {	# ldap authentication
		$ds=ldap_connect($LDAP_SERVER,$LDAP_PORT?$LDAP_PORT:"389");
		if (!$ds) return "LDAP connect: ".ldap_error();
		if ($LDAP_USER) $r=ldap_bind($ds,$LDAP_USER,$LDAP_PASS);
		else $r=ldap_bind($ds);
		if (!$r) return "LDAP bind: ".ldap_error();
		$f = preg_replace('/\\\\u/',$user,preg_replace('/\\\\p/',$pass,$LDAP_FILTER));
		$sr=ldap_search($ds, $LDAP_BASE, $f);
		if (!$sr) return "LDAP search: ".ldap_error();
		$i=ldap_count_entries($ds,$sr);
		ldap_close($ds);
		if ($i>0) return "";

	} elseif ($AUTH_SOURCE==3) {	# mysql authentication
		$link = mysql_pconnect($MYSQL_SERVER.":".($MYSQL_PORT?$MYSQL_PORT:"3306"), $MYSQL_USER, $MYSQL_PASS);
		if (!$link) return "MYSQL connect: ".mysql_error();
		if (!mysql_select_db($MYSQL_DB)) return "MYSQL select db: ".mysql_error();
		$f = preg_replace('/\\\\u/',$user,preg_replace('/\\\\p/',$pass,$MYSQL_QUERY));
		$result = mysql_query($f);
		if (!$result) return "MYSQL query: ". mysql_error();
		$i=mysql_fetch_array($result);
		mysql_free_result($result);
		if ($i) return "";
	}
	return "not authorized";
}

function getmyip ($publicname) {
	// try to get the name wih multiple methods in this order:
	// $publicname: SERVER_ADDR, SERVER_NAME, php_uname, uname, hostname, own script
	// !$publicname: php_uname, uname, hostname, own script, SERVER_ADDR, SERVER_NAME,
	$sysn="";
	if ($publicname) $sysn=$sysn=$_SERVER["SERVER_ADDR"]?$_SERVER["SERVER_ADDR"]:$_SERVER["SERVER_NAME"];
	if (!$sysn || $sysn=="127.0.0.1" || $sysn=="localhost" || preg_match("/\s/",$sysn)) $sysn=php_uname("n");
	if (!$sysn || $sysn=="127.0.0.1" || $sysn=="localhost" || preg_match("/\s/",$sysn)) $sysn=`uname -n`;
	if (!$sysn || $sysn=="127.0.0.1" || $sysn=="localhost" || preg_match("/\s/",$sysn)) $sysn=`hostname`;
	if ($_SERVER["HTTP_HOST"]!="127.0.0.1" && $_SERVER["HTTP_HOST"]!="locahost") {
		$sysurl="http://".$_SERVER["HTTP_HOST"].$_SERVER["PHP_SELF"]."?a=ip";
		$sysn=file_get_contents($sysurl);
		$sysn=preg_replace("/\\r|\\n/","",$sysn);
	}
	if (!$sysn || $sysn=="127.0.0.1" || $sysn=="localhost" || preg_match("/\s/",$sysn))
		$sysn=$_SERVER["SERVER_ADDR"]?$_SERVER["SERVER_ADDR"]:$_SERVER["SERVER_NAME"];
	if (!$sysn) $sysn=$_SERVER["HTTP_HOST"];
	return gethostbyname($sysn);
}
?>