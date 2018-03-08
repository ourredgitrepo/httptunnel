<?php
	if (!isset($_REQUEST["a"])) exit;

	// configuration
	include ("cfg.php");
	$useunix=in_array("unix", stream_get_transports()) && !$IPC_LOADBALANCE;

	function myfwrite ($fd,$buf) {
		$i=0;
		while ($buf != "") {
			$i=fwrite ($fd,$buf,strlen($buf));
			if ($i==false) {
				if (!feof($fd)) continue;
				break;
			}
			$buf=substr($buf,$i);
		}
		return $i;
	}

	// this is for outbound data connections only - this part has been moved to the front for speed
	// send data client connect?
	// need the following REQUEST vars:
	// a: "s"
	// d: control data in the format:
	//		><ipcname>\n<base64enc data>\n...
	if ($_REQUEST["a"]=="s") {
		$ident='';
		$ipsock=0;
		$ret="";
		
		// we need to split these up
		foreach (preg_split('/\n/',$_REQUEST["d"]) as $i) {
			$i=trim($i);
			if ($i == '') continue;
			if (preg_match('/^>(.*)$/',$i,$arr)) {
				// open a new IPC socket to send the next data to
				if ($ident == $arr[1]) continue;
				if ($ipsock) fclose($ipsock);
				$ident = $arr[1];
				if ($useunix) { // this is for the unix socket type
					$sockopen="unix://".preg_replace('/\\\\/','/',$IPC_TMPDIR."tun$ident.sock");
				} else { // this if for the tcp socket type
					preg_match('/^(([^:]+):)?([^:]+)$/',$ident,$matches);
					$port=$matches[3];
					$addr=(isset($matches[2]) && $matches[2])?$matches[2]:"127.0.0.1";
					$sockopen = "tcp://$addr:$port";
				}
				while (!($ipsock = stream_socket_client($sockopen, $errno, $errstr)) &&
						preg_match('/temporarily/',$errstr)) {usleep(rand(1,200000));}
				if (!$ipsock) {
					$ret.="$ident ER stream_socket_client($sockopen) failed: reason: $errstr\n";
					$ident='';
					continue;
				}
			} else {
				if (!$ipsock) continue;
				myfwrite ($ipsock,$i."\n");
				$ret.="$ident OK\n";
			}
		}
		if ($ipsock) fclose($ipsock);
		$ipsock='';
		header("Content-Length: ".strlen($ret));
		echo $ret;
		exit;
	}

	// this is for finding out my IP address in load balanced environments
	if ($_REQUEST["a"] == "ip") {echo $_SERVER["REMOTE_ADDR"];exit;}

	include ("lib.php");

	// check ip of requesting client
	if (!checkip($_SERVER["REMOTE_ADDR"], $SEC_IP)) {
		logline (1,$_SERVER["REMOTE_ADDR"].": Unauthorized access from blocked IP");
		exit;
	}
	
	// start of programm
	register_shutdown_function ("shutdown");
	set_time_limit(0);
	ob_implicit_flush();

	$b=checkuser($_SERVER['PHP_AUTH_USER'],$_SERVER['PHP_AUTH_PW']);
	if ($b) {
		header( "HTTP/1.0 401 Unauthorized" );
		header( "WWW-Authenticate: Basic realm=\"HTTPTunnel\"" );
		logline (1,$_SERVER["REMOTE_ADDR"]." authentication failure - $b");
		id_addaccess($_SERVER["REMOTE_ADDR"]);
		die($b);
	}
	id_delaccess($_SERVER["REMOTE_ADDR"]);

	// no output buffering
	// primary tunnel connect?
	// need the following REQUEST vars:
	// a: "c"
	// s: remote server name
	// p: remote server port
	// sw: package sequence wrap value
	// o: connection options (1 = zlib compressed traffic, 4 = udp)
	if ($_REQUEST["a"]=="c") {
		$outcount=0;
		$incount=0;
		$sequence=0;
		$sw=$_REQUEST["sw"];
		$ka=$TKEEPALIVE_ENABLE;
		$ki=$TKEEPALIVE_INTERVAL;
		$dad=$_REQUEST["s"];
		$dpo=$_REQUEST["p"];

		// check connection options
		$copts=$_REQUEST["o"];
		if (!in_array("zlib",get_loaded_extensions())) $copts &= 254;
		if (!in_array("mcrypt",get_loaded_extensions()) ||
			!in_array("openssl",get_loaded_extensions())) $copts &= 253;

		if (!($copts & 2) && $ENCRYPTION_FORCE) {
			echo "c:s=ER&msg=Tunnel+server+does+not+support+unencrypted+connections\n"; exit;}

		if ($copts & 2) {
			// If we're encrypting, generate a symteric key for ARCFOUR
			$td = mcrypt_module_open(MCRYPT_ARCFOUR, '', MCRYPT_MODE_STREAM, '');
			$te = mcrypt_module_open(MCRYPT_ARCFOUR, '', MCRYPT_MODE_STREAM, '');
			if (!$td || !$te) {
				echo"c:s=ER&msg=Could+not+initialize+Mcrypt+module\n";
				exit;}
			$iv = '';for($i = 0; $i < mcrypt_enc_get_iv_size($td); $i++) $iv .= chr(mt_rand(0,255));
			$key = '';for($i = 0; $i < mcrypt_enc_get_key_size($td); $i++) $key .= chr(mt_rand(0,255));
			mcrypt_generic_init($td, $key, $iv);
			mcrypt_generic_init($te, $key, $iv);
			$pkey=$_REQUEST["pk"];
			$pkey="-----BEGIN PUBLIC KEY-----\n".rtrim(preg_replace('/(.{1,64})/',"\\1\n",$pkey))."\n-----END PUBLIC KEY-----";
			$symkey=base64_encode(ssl_encrypt($iv.$key,$pkey));
		}

		// open the remote socket
		$msg=openRemote($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
		if ($msg) {
			echo "c:s=ER&msg=".urlencode("REMOTE $msg")."\n";exit;}
		if ($rmsock) stream_set_blocking($rmsock,1);
		
		// open the interprocess socket
		if ($useunix) {	// this is for the unix socket type
			$ident=stream_socket_get_name($rmsock?$rmsock:$usock,false);
			$ident=preg_replace('/^.*?:/','',$ident);
			$sockname=preg_replace('/\\\\/','/',$IPC_TMPDIR."tun$ident.sock");
			unlink($sockname);
			if (file_exists($sockname)) {
				echo "c:s=ER&msg=".urlencode("Temporary UNIX socket exists and cannot be deleted ($sockname)")."\n";
				exit;
			}
			$ipsock = stream_socket_server("unix://$sockname", $errno, $errstr);
			if (!$ipsock) {
				echo "c:s=ER&msg=".urlencode("stream_socket_server(unix://$sockname) failed: $errstr")."\n";exit;}

		} else {	// this if for the tcp socket type
			$ipsock = stream_socket_server("tcp://".($IPC_LOADBALANCE?"0.0.0.0":"127.0.0.1").":0", $errno, $errstr);
			if (!$ipsock) {
				echo "c:s=ER&msg=".urlencode("stream_socket_server() failed: reason: $errstr")."\n";
				exit;
			}
			$ident=stream_socket_get_name($ipsock,false);
			$ident=preg_replace('/^.*?:/','',$ident);

			// try to get the system name
			$ident=($IPC_LOADBALANCE?getmyip(false).":":"").$ident;
		}
		stream_set_blocking($ipsock,0);

	    logline (2,$copts & 4?
    	"$ident: New tunnel established ".$_SERVER["REMOTE_ADDR"]." sending UDP packets":
    	($copts & 8?
    	"$ident: New tunnel established ".$_SERVER["REMOTE_ADDR"]." listening on port $bpo":
    	"$ident: New tunnel established ".$_SERVER["REMOTE_ADDR"]." -> $dad:$dpo"));
		echo "c:s=OK&o=$copts&i=$ident&sn=$bad&sp=$bpo".($copts & 2?"&k=".urlencode($symkey):"")."\n";

		// ok, we created both sockets .. now listen on both
		while (ob_get_level() > 0) ob_end_flush();
		if ($ka) $nk=time()+$ki;
		$copts &= 239;
		while (true) {
			// set up the handles to listen on
			$rin = array($ipsock);
			if ($rmsock) $rin[]=$rmsock; # listen on tcp socket if applicable
			if ($usock) $rin[]=$usock; # listen on udp socket if applicable
			$ti=time();
			$write = $except = null;
			stream_select($rin, $write, $except, $ka?($nk-$ti<=0?0:$nk-$ti):null);
			if ($ka and time()>=$nk) {
				echo "\n";
				$nk=time()+$ki;
				continue;
			}
			
			if ($rin[0]==$ipsock) {
				// ok, we got an interprocess connecting, that means were piping the data from $ipsock to $rmsock
				if (($c_ipsock=stream_socket_accept ($ipsock))===false) continue;
				$inbuf='';
				while (!feof($c_ipsock)) $inbuf .= fread($c_ipsock, 8192);
				fclose($c_ipsock);
				$inbuf=preg_replace('/\r/','',$inbuf);
				logline(4,"$ident: Got something from IPC: $inbuf");
				foreach (preg_split('/\n/',$inbuf) as $i) {
					if ($i=="") continue;
					if (preg_match('/^(\d+):(.*)$/',$i,$matches)) {
						# we have data coming in .. check the sequence and send to rserver
						# drop dupes
						if (!isset($sequence_buffer[$matches[1]])) {
							$sequence_buffer[$matches[1]] = $matches[2];
							logline(4, "$ident: Got seq ".$matches[1].", expected seq $sequence");
						
							while(isset($sequence_buffer[$sequence])) {
								if (preg_match('/^c:disconnect/',$sequence_buffer[$sequence])) {
									echo "c:disconnect on request client\n";
									logline (2,"$ident: Disconnect on request client");
									logline (2,"$ident: Sent ".$outcount." bytes, received ".$incount." bytes");
									exit;
								} else {
									$buf=base64_decode($sequence_buffer[$sequence]);
									if ($copts & 2) $buf=mdecrypt_generic($td, $buf);
									if ($copts & 1) $buf=gzuncompress($buf);
									unset($sequence_buffer[$sequence]);
									unset($sequence_buffer[$sequence+(($sequence-floor($sw/2))<0?$sw:0)-floor($sw/2)]);
									$i=strlen($buf);
									if ($copts & 4) { # udp package processing
										# in case were cascading, we're forwarding the package 'as is'
										$i=$i-7-(ord(substr($buf,3,1))==1?3:ord(substr($buf,4,1)));
										if (!$CASCADING) {
											if (ord(substr($buf,3,1))==1) {
												$arr=unpack("N",substr($buf,4,4));
												$s=long2ip($arr[1]);
												$buf=substr_replace($buf,"",0,8);
											} else {
												$s=substr($buf,5,ord(substr($buf,4,1)));
												$buf=substr_replace($buf,"",0,5+ord(substr($buf,4,1)));
											}
											$p=unpack("n",substr($buf,0,2));
											$buf=substr_replace($buf,"",0,2);
										} else {$s=$bad;$p[1]=$bpo;}
										stream_socket_sendto($usock, $buf, 0, "$s:$p[1]");
									} else { # tcp package processing
										myfwrite($rmsock,$buf);
									}
									logline(3,"$ident: -> ".bin2txt(substr($buf,-$i)));
									$outcount+=$i;
									$sequence++;$sequence %= $sw;
								}
							}
						} else {
							logline(2,"$ident: WARNING - Dupe package received seq ".$matches[1].", expected seq $sequence");
						}
					} else {
						echo "l:1 Got a line I could not understand: '$i'\n";
						if ($ka) $nk=time()+$ki;
					}
				}
			}

			elseif (($rmsock && $rin[0]==$rmsock) || ($usock && $rin[0]==$usock)) {
				// we got data coming in from the remote port, lets dump it to the client
				if (($copts & 24) == 8) { # BIND should accept the connection
					logline (4,"$ident: client trying to connect to bound socket");
					if ($CASCADING == 4) {
						$a=get_socks4_reply($rmsock);
						if ($a[0]) {
							echo "c:disconnect $a[0]\n";exit;}
					} elseif ($CASCADING == 5) {
						$a=get_socks5_reply($rmsock);
						if ($a[0]) {
							echo "c:disconnect $a[0]\n";exit;}
					} else {
						if (($rmsock1=stream_socket_accept ($rmsock))===false) {
							echo "c:disconnect BIND accept failed\n";exit;}
						fclose($rmsock);
						$rmsock=$rmsock1;
						$a[1]=preg_replace('/:.*$/','',stream_socket_get_name($rmsock,true));
						$a[2]=preg_replace('/^.*?:/','',stream_socket_get_name($rmsock,true));
					}
					logline (4,"$ident: $a[1] connecting to bound socket");
					echo "b:$a[1]:$a[2]\n";
					if ($ka) $nk=time()+$ki;
					$copts|=16;
					continue;
				}
				if (($rmsock && feof($rmsock)) || ($usock && feof($usock))) {
					echo "c:disconnect on request server\n";
				    logline (2,"$ident: Disconnect on request server");
					logline (2,"$ident: Sent ".$outcount." bytes, received ".$incount." bytes");
					exit;
				}
				if ($rin[0]==$usock) $buf=stream_socket_recvfrom($usock,65536,0,$addr);
				else $buf=fread($rmsock,65536);
				$i=strlen($buf);

				if (!empty($buf)) {
					if ($copts & 4) {
						if (!$CASCADING) {
							list($s,$p)=preg_split('/:/',$addr);
							$buf="\000\000\000\001".pack("N",ip2long($s)).pack("n",$p).$buf;
						} else {$i-=10;}
					}
					logline(3,"$ident: <- ".bin2txt(substr($buf,-$i)));
					$incount+=$i;
					if ($copts & 1) $buf=gzcompress($buf,9);
					if ($copts & 2) $buf=mcrypt_generic($te, $buf);
					echo base64_encode($buf)."\n";
					if ($ka) $nk=time()+$ki;
				}
			}
		}
	}
?>