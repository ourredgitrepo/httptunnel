<?php
	// configuration 
	include ("cfg.php");
	include ("lib.php");

	// check ip of requesting client
	if (!checkip($_SERVER["REMOTE_ADDR"], $ADMIN_IP)) {
		logline (1,$_SERVER["REMOTE_ADDR"].": Unauthorized access to admin interface from blocked IP");
		exit;
	}

	// check authorization
	if ($ADMIN_AUTH_USER && ($_SERVER['PHP_AUTH_USER']!=$ADMIN_AUTH_USER || $_SERVER['PHP_AUTH_PW']!=$ADMIN_AUTH_PASS)) {
		header( "WWW-Authenticate: Basic realm=\"HTTPTunnel Admin\"" );
		header( "HTTP/1.0 401 Unauthorized" );
		id_addaccess($_SERVER["REMOTE_ADDR"]);
		die ('Authorization Required!');
	}
	id_delaccess($_SERVER["REMOTE_ADDR"]);

	if ($_REQUEST["d_action"] == "log") {
		set_time_limit(0);
		ob_implicit_flush();
		$size=isset($_REQUEST["size"])?$_REQUEST["size"]:65536;
		?>
		<html>
		<head>
		<title>HTTPTunnel Server Log</title>
		<META HTTP-EQUIV="Expires" CONTENT="Mon, 06 Jan 1990 00:00:01 GMT">
		<link type="text/css" rel="StyleSheet" href="common/tab.css" />
		<script>
			function s() {
				window.scrollBy(0,9999999);
			}
		</script>
		</head>
		<body style="background-color:#FCFCFE; margin:3px">
		<?php
		# dump out last $size bytes of the logfile
		if (!($LOG1=fopen ($LOGFILE, "r"))) die("cannot open logfile $LOGFILE");
		$lstat=fstat($LOG1);
		fseek($LOG1,$lstat["size"]<$size?0:$lstat["size"]-$size);
		$trans = get_html_translation_table();
		$trans["\n"]="<br>";
		while($i=fread($LOG1,65536)) echo strtr($i, $trans);
		echo "<script>s();</script>\n";
		ignore_user_abort(false);
		while (1) {
			usleep(500000);
			if ($i=fread($LOG1,65536)) echo strtr($i, $trans)."<script>s();</script>\n";
		}
		
		exit;
	}
	
	if ($_REQUEST["d_action"] == "save") {
		$buf="<?php\n";
		foreach (array_keys($_POST) as $i) {
			if (!preg_match('/^[A-Z][A-Z_]+$/',$i)) continue;
			# work around stupid magic quotes :-(
			if (get_magic_quotes_gpc()) $_POST[$i]=preg_replace("/\\\\([\"'\\\\\\000])/","$1",$_POST[$i]);
			$buf.="$".$i." = \"".addcslashes(preg_replace('/\r/','',$_POST[$i]),"\\\"\n")."\";\n";
		}
		$buf.="?".">\n";
		$fh=fopen("cfg.php","w");
		if (!$fh) {
			?><html>
			<head>
			<title>HTTPTunnel Server Log</title>
			<META HTTP-EQUIV="Expires" CONTENT="Mon, 06 Jan 1990 00:00:01 GMT">
			<link type="text/css" rel="StyleSheet" href="common/tab.css" />
			</head>
			<body style="background-color:#FCFCFE; margin:3px">
			<table class="warning">
			<tr><td><b>Could not open file cfg.php for writing!</b><p>
			Please edit the file manually and replace it with the contents of the textarea below. After changing the configuration manually, please click <a href="admin.php">here</a>.</td></tr>
			</table>
			<form><textarea style="width:600px;height:400px"><?php
			echo htmlspecialchars($buf);
			?></textarea></form></body></html><?php
			exit;
		}
		fwrite ($fh,$buf);
		fclose($fh);
		include ("cfg.php");
		logline(1,$_SERVER["REMOTE_ADDR"]." Config changed by admin");
		$msg="Configuration saved successfully";
	}
?>
<html>
<head>
<title>HTTPTunnel PHP Server Administration</title>
<link rel="shortcut icon" href="common/server.ico" type="image/x-icon" />
<link type="text/css" rel="StyleSheet" href="common/tab.css" />
<script type="text/javascript" src="common/tabpane.js"></script>
<script type="text/javascript" src="common/overlib_mini.js"></script>
<script>
	function initAddUser() {
		var dialog=window.open('','user','height=130,width=385,dependent=yes,directories=no,location=no,menubar=no,resizable=yes,scrollbars=no,status=no,toolbar=no');
		dialog.document.write(getUserHTML('Add','','',-1));
		dialog.document.close();
	}
	function initModUser() {
		var sel=document.adminform.d_SOCKS_USER;
		if (sel.selectedIndex==-1) return;
		var a=parseUser(sel.options[sel.selectedIndex].text);
		dialog=window.open('','user', 'height=130,width=385,dependent=yes,directories=no,location=no,menubar=no,resizable=yes,scrollbars=no,status=no,toolbar=no');
		dialog.document.write(getUserHTML('Modify',a[1],a[2],sel.selectedIndex));
		dialog.document.close();
	}

	function parseUser(s) {return s.match(/^([^:]+):(.*)$/);}
	function removeSel(name) {
		var sel=document.adminform.elements[name];
		var i=sel.selectedIndex;
		if (i==-1) return;
		sel.options[i]=null;
		if (sel.length>i) sel.selectedIndex=i;
		else sel.selectedIndex=sel.length-1;
	}

	function cmpOptionsInt(a,b) {return (parseInt(a.value)-parseInt(b.value));}
	function cmpOptionsStr(a,b) {return a<b?-1:(a>b?1:0);}
	function addmodOption(isInt,name,idx,text,value) {
		var sel=document.adminform.elements[name];
		var a=new Array();var x=-1,i;
		for (i=0;i<sel.length;i++) a[i]=sel.options[i];
		a[idx==-1?a.length:idx]=new Option(text,value);
		a.sort(isInt?cmpOptionsInt:cmpOptionsStr);
		for (i=0;i<a.length;i++) {sel.options[i]=a[i];if (a[i].value==value) x=i;}
		sel.selectedIndex=x;
	}

	function ableAuth() {
		var i=document.adminform.d_AUTH_METHOD[0].checked;
		var r=document.adminform.d_AUTH_SOURCE;
		for (var x=0;x<r.length;x++) r[x].disabled=(r[x].className=="noinp")?true:i;
		document.adminform.d_AUTH_USER.disabled=i;
		document.adminform.d_USADD.disabled=i;
		document.adminform.d_USDEL.disabled=i;
		document.adminform.d_USMOD.disabled=i;
		document.getElementById('authtab').style.visibility=i?"hidden":"visible";
	}

	function ableID() {
		var i=!document.adminform.d_ID_ENABLE.checked;
		document.adminform.d_ID_TIMEOUT.disabled=i;
		document.adminform.d_ID_BANTIMEOUT.disabled=i;
		document.adminform.d_ID_MAXACCESS.disabled=i;
	}

	function showAuth() {
		var r=document.adminform.d_AUTH_SOURCE;
		var idx=0;
		for (var x=0;x<r.length;x++) if (r[x].checked) break;
		document.getElementById('authtab').tabPane.setSelectedIndex(x);
	}

	function ableCas() {
		var i=document.adminform.d_CASCADING[0].checked;
		document.adminform.d_CAS_SERVER.disabled=i;
		document.adminform.d_CAS_PORT.disabled=i;
		document.adminform.d_CAS_AUTH_PASS.disabled=(i | document.adminform.d_CASCADING[1].checked);
		document.adminform.d_CAS_AUTH_USER.disabled=i;
		document.adminform.d_CAS_AUTH_PASSTHROUGH.disabled=i;
	}

	function ableTKeep() {
		var i=!document.adminform.d_TKEEPALIVE_ENABLE.checked;
		document.adminform.d_TKEEPALIVE_INTERVAL.disabled=i;
	}

	function ableIPC() {
		var i=document.adminform.d_IPC_LOADBALANCE.checked;
		document.adminform.d_IPC_TMPDIR.disabled=i;
	}

	function getUserHTML (action,user,pass,idx) {
		var ret='\
		<head><title>'+action+' User</title>\n\
		<link type="text/css" rel="StyleSheet" href="common/tab.css" />\n\
		<script>\n\
			function doAddUser() {\n\
				var i,lfo,rfo,sel;\n\
				lfo=document.pm;rfo=window.opener.document.adminform;sel=rfo.d_AUTH_USER;\n\
				if (lfo.user.value == "") {alert("Please specify a username!");return;}\n\
				for(i=0;i<sel.length;i++){if (i!='+idx+' && sel.options[i].value==lfo.user.value) {alert("Username "+lfo.user.value+" already exists!");return;}}\n\
				window.opener.addmodOption(0,"d_AUTH_USER",'+(idx==-1?'-1':idx)+', lfo.user.value+":"+lfo.pass.value, lfo.user.value);\n\
				window.close();\n\
			}\n\
		</'+'script></head><body onLoad="document.pm.user.focus()" style="background:ThreeDFace;margin-right:30px;"><form name="pm">\n\
		<div class="input-pane"><table border=0 cellpadding=0 cellspacing=3 width=100%>\n\
		<tr><th colspan=2>'+action+' User</th></tr>\n\
		<tr><td>Username:</td><td><input name="user" style="width:100px" value="'+user+'"></td></tr>\n\
		<tr><td>Password:</td><td><input name="pass" style="width:100px" value="'+pass+'"></td></tr>\n\
		<tr><td colspan=2 align="center"><input type="submit" value="OK" onClick="doAddUser();return false;" style="width:70">\n\
		<input type="button" value="Cancel" onClick="window.close()" style="width:70"></td></tr>\n\
		</table></div></form></body>';
		return ret;
	}

	// get a field value no matter what type of field it is
	function getValue(i) {
		var e=document.adminform.elements[i];
		var ret="";
		if (!e) alert (i);
		switch (e.type) {
		case "select-one":
		case "select-multiple":
			for (var i=0;i<e.length;i++) if (e.options[i].selected) ret+=(ret==""?"":"|")+e.options[i].value;
			break;
		case "checkbox":
			ret= e.checked?e.value:"";
			break;
		default:
			if (e[0] && e[0].type=="radio") {for (var i=0;i<e.length;i++) if (e[i].checked) {ret=e[i].value;break;}}
			else ret=e.value;
		}
		return ret;
	}

	function trim(i) {
		document.adminform.elements[i].value=getValue(i).replace(/\s/g,"");
	}

	function push(arr,msg,i) {
		arr.push(msg);
		if (i) document.adminform.elements[i].className="marked";
	}

	function clearMarks() {
		var i;
		for (i=0;i<document.adminform.elements.length;i++)
			if (document.adminform.elements[i].type=="text") document.adminform.elements[i].className="";
	}

	function submitForm () {
		var i,sel,s,a,f;
		f=document.adminform;
		// check form here
		clearMarks();
		var warnings=new Array();
		var errors= new Array();

		// check tab1 *****************
		trim("d_SEC_IP");
		trim("d_LDAP_SERVER");trim("d_LDAP_PORT");trim("d_MYSQL_SERVER");trim("d_MYSQL_PORT");
		trim("d_MYSQL_USER");trim("d_MYSQL_DB");trim("d_SEC_IP");

		if (getValue("d_AUTH_METHOD")=="basic") {
			switch (getValue("d_AUTH_SOURCE")) {
			case "1":
				//check Fixed User List
				if (f.d_AUTH_USER.length<1)
					push(warnings,"HTTP authentication is set to use the fixed user list, but no users are configured","");
				break;
			case "2":
				// check LDAP
				if (!f.d_LDAP_SERVER.value)	push(errors,"Please specify an LDAP server name","d_LDAP_SERVER");
				if (isNaN(parseInt(f.d_LDAP_PORT.value)) || parseInt(f.d_LDAP_PORT.value)<=0)
					push(errors,"Please specify a numeric LDAP service port number","d_LDAP_PORT");
				if (!f.d_LDAP_FILTER.value)	push(errors,"Please specify an LDAP filter","d_LDAP_FILTER");
				break;
			case "3":
				// check MySQL
				if (!f.d_MYSQL_SERVER.value) push(errors,"Please specify a MySQL server name","d_MYSQL_SERVER");
				if (isNaN(parseInt(f.d_MYSQL_PORT.value)) || parseInt(f.d_MYSQL_PORT.value)<=0)
					push(errors,"Please specify a numeric MySQL service port number","d_MYSQL_PORT");
				if (!f.d_MYSQL_DB.value) push(errors,"Please specify a MySQL database name","d_MYSQL_DB");
				if (!f.d_MYSQL_QUERY.value) push(errors,"Please specify a MySQL query","d_MYSQL_QUERY");
				break;
			}
		}
		// check SECIP
		if (f.d_SEC_IP.value && !f.d_SEC_IP.value.match(/((^|,)\d+\.\d+\.\d+\.\d+(\/\d+)?)+$/))
			push(errors,"Limit access to IPs must be in the format x.x.x.x[/x][,...]","d_SEC_IP");

		// check tab2 *****************
		trim("d_CAS_SERVER");trim("d_CAS_PORT");

		if (getValue("d_CASCADING")>"0") {
			if (!f.d_CAS_SERVER.value) push(errors,"Please specify a cascading server name","d_CAS_SERVER");
			if (isNaN(parseInt(f.d_CAS_PORT.value)) || parseInt(f.d_CAS_PORT.value)<=0)
				push(errors,"Please specify a numeric cascading server port number","d_CAS_PORT");
		}

		// check tab3 *****************
		trim("d_LOGLEVEL");trim("d_MAXLOGSIZE");

		if (isNaN(parseInt(f.d_LOGLEVEL.value)) || parseInt(f.d_LOGLEVEL.value)<0)
			push(errors,"Please specify a numeric loglevel","d_LOGLEVEL");
		if (parseInt(f.d_LOGLEVEL.value)>0) {
			if (!f.d_LOGFILE.value) push(errors,"Please specify a log filename","d_LOGFILE");
			if (isNaN(parseInt(f.d_MAXLOGSIZE.value)) || parseInt(f.d_MAXLOGSIZE.value)<=0)
				push(errors,"Please specify a numeric maximum logfile size","d_MAXLOGSIZE");
			if (parseInt(f.d_MAXLOGSIZE.value)<100000)
				push(warnings,"Maximum logfile size should be at least 100 kbytes","");
		}

		// check tab4 *****************
		trim("d_TKEEPALIVE_INTERVAL");

		if (getValue("d_TKEEPALIVE_ENABLE") && (isNaN(parseInt(f.d_TKEEPALIVE_INTERVAL.value)) || parseInt(f.d_TKEEPALIVE_INTERVAL.value)<=0))
			push(errors,"Please specify a numeric tunnel keepalive interval in seconds","d_TKEEPALIVE_INTERVAL");
			
		if (f.d_IPC_TMPDIR.type=="text" && !f.d_IPC_TMPDIR.disabled && !f.d_IPC_TMPDIR.value)
			push(errors,"Please specify a temporary directory for the UNIX IPC socket files","d_IPC_TMPDIR");
		else {
			var t=f.d_IPC_TMPDIR.value;
			t=t.replace(/\\/g,"/");
			if (t.substr(-1,1)!="/") t+="/";
			f.d_IPC_TMPDIR.value=t;
		}

		if (getValue('d_ID_ENABLE')) {
			if (isNaN(parseInt(f.d_ID_MAXACCESS.value)) || parseInt(f.d_ID_MAXACCESS.value)<1)
				push(errors,"Please specify the maximum amount of login attempts","d_ID_MAXACCESS");
			if (isNaN(parseInt(f.d_ID_TIMEOUT.value)) || parseInt(f.d_ID_TIMEOUT.value)<1)
				push(errors,"Please specify a valid Intrusion Detection interval in seconds","d_ID_TIMEOUT");
			if (isNaN(parseInt(f.d_ID_BANTIMEOUT.value)) || parseInt(f.d_ID_BANTIMEOUT.value)<1)
				push(errors,"Please specify a valid client ban period in seconds","d_ID_BANTIMEOUT");
		}

		if (f.d_ADMIN_IP.value && !f.d_ADMIN_IP.value.match(/((^|,)\d+\.\d+\.\d+\.\d+(\/\d+)?)+$/))
			push(errors,"Limit access to IPs for admin web interface must be in the format x.x.x.x[/x][,...]","d_ADMIN_IP");
		if (!f.d_ADMIN_AUTH_USER.value)
			push(warnings,"The admin web interface does not require login","");
		else if (!f.d_ADMIN_AUTH_PASS.value)
			push(warnings,"The admin web interface login does not have a password set","");

		if (errors.length) {
			alert ("ERRORS occurred while validating your input:\n- "+errors.join("\n- "));
			return false;
		}

		// transfer values to hidden fields
		f.AUTH_METHOD.value=getValue('d_AUTH_METHOD');
		f.AUTH_SOURCE.value=getValue('d_AUTH_SOURCE');
		s="";
		sel=f.d_AUTH_USER;
		for (i=0;i<sel.length;i++) {
			if (sel.options[i].text=="") continue;
			s+=(s==""?"":"\n")+sel.options[i].text;
		}
		f.AUTH_USER.value=s;
		f.CASCADING.value=getValue('d_CASCADING');
		f.CAS_SERVER.value=getValue('d_CAS_SERVER');
		f.CAS_PORT.value=getValue('d_CAS_PORT');
		f.CAS_AUTH_USER.value=getValue('d_CAS_AUTH_USER');
		f.CAS_AUTH_PASS.value=getValue('d_CAS_AUTH_PASS');
		f.CAS_AUTH_PASSTHROUGH.value=getValue('d_CAS_AUTH_PASSTHROUGH');
		f.LOGLEVEL.value=getValue('d_LOGLEVEL');
		f.LOGFILE.value=getValue('d_LOGFILE');
		f.MAXLOGSIZE.value=getValue('d_MAXLOGSIZE');
		f.TKEEPALIVE_ENABLE.value=getValue('d_TKEEPALIVE_ENABLE');
		f.TKEEPALIVE_INTERVAL.value=getValue('d_TKEEPALIVE_INTERVAL');
		f.IPC_LOADBALANCE.value=getValue('d_IPC_LOADBALANCE');
		f.IPC_TMPDIR.value=getValue('d_IPC_TMPDIR');
		f.ID_ENABLE.value=getValue('d_ID_ENABLE');
		f.ID_TIMEOUT.value=getValue('d_ID_TIMEOUT');
		f.ID_BANTIMEOUT.value=getValue('d_ID_BANTIMEOUT');
		f.ID_MAXACCESS.value=getValue('d_ID_MAXACCESS');
		f.ENCRYPTION_FORCE.value=getValue('d_ENCRYPTION_FORCE');
		f.ADMIN_IP.value=getValue('d_ADMIN_IP');
		f.ADMIN_AUTH_USER.value=getValue('d_ADMIN_AUTH_USER');
		f.ADMIN_AUTH_PASS.value=getValue('d_ADMIN_AUTH_PASS');
		f.LDAP_SERVER.value=getValue('d_LDAP_SERVER');
		f.LDAP_PORT.value=getValue('d_LDAP_PORT');
		f.LDAP_USER.value=getValue('d_LDAP_USER');
		f.LDAP_PASS.value=getValue('d_LDAP_PASS');
		f.LDAP_BASE.value=getValue('d_LDAP_BASE');
		f.LDAP_FILTER.value=getValue('d_LDAP_FILTER');
		f.MYSQL_SERVER.value=getValue('d_MYSQL_SERVER');
		f.MYSQL_PORT.value=getValue('d_MYSQL_PORT');
		f.MYSQL_USER.value=getValue('d_MYSQL_USER');
		f.MYSQL_PASS.value=getValue('d_MYSQL_PASS');
		f.MYSQL_DB.value=getValue('d_MYSQL_DB');
		f.MYSQL_QUERY.value=getValue('d_MYSQL_QUERY');
		f.SEC_IP.value=getValue('d_SEC_IP');

		return confirm(
		(warnings.length?("WARNING !!\n- "+warnings.join("\n- ")+"\n\n"):"")+
		"Would you "+(warnings.length?"still ":"")+"like to save your changes?\n\n");
	}

	function refreshStatus() {
		window.frames["stats"].location.reload()
	}
	function hidePl() {
		document.getElementById('movie').style.visibility='hidden';
	}
	function showPl() {
		document.getElementById('movie').style.visibility='visible';
	}
</script>
</head>
<body style="background:ThreeDFace" onLoad="ableAuth();showAuth();ableCas();ableTKeep();ableIPC();ableID();">
<div id="overDiv" style="position:absolute; visibility:hidden; z-index:1000;"></div>
<form name="adminform" action="<?php echo $_SERVER["SCRIPT_NAME"]?>" method="POST">
<input type="hidden" name="d_action" value="save">
<div class="tab-pane">
<h1><img src="common/cpanel.png"> HTTPTunnel PHP Server Administration</h1>
<?php
	$note="";
	if (!in_array("zlib",get_loaded_extensions())) $note.="<tr><td> - </td><td>WARNING: PHP Extension Zlib not installed. Server does not support compression.</td></tr>";
	if (!in_array("mcrypt",get_loaded_extensions()) ||
		!in_array("openssl",get_loaded_extensions())) $note.="<tr><td> - </td><td>WARNING: PHP Extension OpenSSL and/or Mcrypt not installed. Server does not support encryption.</td></tr>";
	if ($note) { ?>
	<table class="warning">
	<tr><td colspan=2><b>HTTPTunnel server messages:</b></td></tr>
	<?php echo $note;?>
	</table>
<?php } ?>
<?php if ($msg) echo "<h1><font color='#E68B2C' size='3'>$msg</font></h1>"; ?>
<div class="tab-pane" style="width: 600">
   <div class="tab-page">
      <h2 class="tab">Tunnel Server</h2>
		<table border=0 cellpadding=0 cellspacing=3 width=100%>
		<tr><th colspan=2><img src="common/info.gif" onmouseover="return overlib(
'<b>Authentication Method</b>:<br>Does the PHP tunnel script require authentication? Currently, only basic authentication is supported.', CAPTION, 'HTTPTunnel Server Settings');" onmouseout="return nd();"> HTTPTunnel Server Settings</th></tr>
		<tr><td valign="top">
			<table border=0 cellpadding=0 cellspacing=0 width=100%>
			<tr><td style="padding-bottom:3px">HTTP Authentication Method:</td>
				<td style="padding-bottom:3px">
				<input type="radio" name="d_AUTH_METHOD" onClick="ableAuth();" value="none"<?php echo $AUTH_METHOD == "none"?" checked":""?>> None<br>
				<input type="radio" name="d_AUTH_METHOD" onClick="ableAuth();" value="basic"<?php echo $AUTH_METHOD == "basic"?" checked":""?>> Basic</td></tr>
			<tr><th colspan=2>Authentication Source</th></tr>
			<tr><td colspan=2>
				<input type="radio" name="d_AUTH_SOURCE" style="vertical-align:middle;margin-right:10px" onClick="showAuth()" value="1"<?php echo $AUTH_SOURCE==1?" checked":""?>>Fixed User list<br>
				<input type="radio" name="d_AUTH_SOURCE" style="vertical-align:middle;margin-right:10px" onClick="showAuth()" disabled value="2"<?php echo $AUTH_SOURCE==2?" checked":""?><?php echo in_array("ldap",get_loaded_extensions())?"":" class='noinp'"?>>LDAP<?php echo in_array("ldap",get_loaded_extensions())?"":" - <font color=red>Not supported by PHP installation</font>"?><br>
				<input type="radio" name="d_AUTH_SOURCE" style="vertical-align:middle;margin-right:10px" onClick="showAuth()" disabled value="3"<?php echo $AUTH_SOURCE==3?" checked":""?><?php echo in_array("mysql",get_loaded_extensions())?"":" class='noinp'"?>>MySQL<?php echo in_array("mysql",get_loaded_extensions())?"":" - <font color=red>Not supported by PHP installation</font>"?>
			</td></tr></table>
		</td><td valign="top">
		<div id="authtab" class="tab-pane" style="width: 350; float:right">
			<div class="tab-page">
			<h2 class="tab">User List</h2>
			<table border=0 cellpadding=0 cellspacing=0 width="100%">
				<tr><th>Fixed User List Authentication Settings</th></tr>
				<tr><td style="padding-top:3px">
				<select name="d_AUTH_USER" size=6 style="width:200;float:left">
<?php
	foreach (preg_split('/\n/',$AUTH_USER) as $i) {
		if ($i=="") continue;
		$a=preg_split('/:/',$i);
		echo "<option value=\"$a[0]\">$a[0]:$a[1]</option>\n";
	}
?>
				</select>
				<input type="button" value="Add" name="d_USADD" onClick="initAddUser()" style="width:70"><br>
				<input type="button" value="Remove" name="d_USDEL" onClick="removeSel('d_AUTH_USER')" style="width:70"><br>
				<input type="button" value="Modify" name="d_USMOD" onClick="initModUser()" style="width:70"><br>
				</td></tr></table>
			</div>
			<div class="tab-page">
			<h2 class="tab">LDAP</h2>
			<table border=0 cellpadding=0 cellspacing=0 width=100%>
				<tr><th colspan=2><img src="common/info.gif" onmouseover="return overlib(
'<b>Filter</b>:<br>This is the query that is sent to the LDAP server. If the query returns any entries, authentication is successful. The character sequences \'\\u\' and \'\\p\' are replaced by the username and password provided by the HTTP client. Example of a filter:<br>(&(uid=\\u) (pass=\\p))', CAPTION, 'LDAP Authentication Settings');" onmouseout="return nd();"> LDAP Authentication</th></tr>
				<tr><td style="padding-top:3px">Server:</td><td style="padding-top:3px"><input name="d_LDAP_SERVER" style="width:200px" value="<?php echo $LDAP_SERVER?>"></td></tr>
				<tr><td>Port:</td><td><input name="d_LDAP_PORT" style="width:50px" value="<?php echo $LDAP_PORT?>"></td></tr>
				<tr><td>Username / Password:</td><td>
					<input name="d_LDAP_USER" style="width:98px" value="<?php echo $LDAP_USER?>">
					<input name="d_LDAP_PASS" style="width:98px" value="<?php echo $LDAP_PASS?>"></td></tr>
				<tr><td>Base DN:</td><td><input name="d_LDAP_BASE" style="width:200px" value="<?php echo $LDAP_BASE?>"></td></tr>
				<tr><td>Filter:</td><td><input name="d_LDAP_FILTER" style="width:200px" value="<?php echo $LDAP_FILTER?>"></td></tr>
				</table>
			</div>
			<div class="tab-page">
			<h2 class="tab">MySQL</h2>
			<table border=0 cellpadding=0 cellspacing=0 width=100%>
				<tr><th colspan=2><img src="common/info.gif" onmouseover="return overlib(
'<b>Query</b>:<br>This is the query that is sent to the MySQL server. If the query returns any entries, authentication is successful. The character sequences \'\\u\' and \'\\p\' are replaced by the username and password provided by the HTTP client. Example of a query:<br>SELECTt * FROM users WHERE uid=\'\\u\' AND pass=PASSWORD(\'\\p\')', CAPTION, 'MySQL Authentication Settings');" onmouseout="return nd();"> MySQL Authentication</th></tr>
				<tr><td style="padding-top:3px">Server:</td><td style="padding-top:3px"><input name="d_MYSQL_SERVER" style="width:200px" value="<?php echo $MYSQL_SERVER?>"></td></tr>
				<tr><td>Port:</td><td><input name="d_MYSQL_PORT" style="width:50px" value="<?php echo $MYSQL_PORT?>"></td></tr>
				<tr><td>Username / Password:</td><td>
					<input name="d_MYSQL_USER" style="width:98px" value="<?php echo $MYSQL_USER?>">
					<input name="d_MYSQL_PASS" style="width:98px" value="<?php echo $MYSQL_PASS?>"></td></tr>
				<tr><td>Database:</td><td><input name="d_MYSQL_DB" style="width:200px" value="<?php echo $MYSQL_DB?>"></td></tr>
				<tr><td>Query:</td><td><input name="d_MYSQL_QUERY" style="width:200px" value="<?php echo $MYSQL_QUERY?>"></td></tr>
				</table>
			</div>
		</div>
		</td></tr>
		<tr><th colspan=2><img src="common/info.gif" onmouseover="return overlib(
'<b>Limit access to IPs</b><br>A comma delimited list of IP adresses (netmask can be supplied) that are allowed to access the HTTPTunnel server, e.g. 127.0.0.1,10.0.0.0/8<br>Leave blank for no restrictions.<br>', CAPTION, 'Security Settings');" onmouseout="return nd();"> Security</th></tr>
		<tr><td>Limit access to IPs:</td><td width=90%><input name="d_SEC_IP" style="width:200px" value="<?php echo $SEC_IP?>"></td></tr>
		</table>
   </div>
	<div class="tab-page">
		<h2 class="tab">Cascading</h2>
		<table border=0 cellpadding=0 cellspacing=3 width=100%>
		<tr><th colspan=2><img src="common/info.gif" onmouseover="return overlib(
'Connections to the remote hosts can be made over a SOCKS4 or SOCKS5 proxy. Configure the SOCKS cascading here', CAPTION, 'SOCKS Cascading Settings');" onmouseout="return nd();"> SOCKS Cascading</th></tr>
		<tr><td width=30%>Cascading enabled:</td><td>
			<input type="radio" name="d_CASCADING" onClick="ableCas();" value="0"<?php echo $CASCADING == 0?" checked":""?>> disabled
			<input type="radio" name="d_CASCADING" onClick="ableCas();" value="4"<?php echo $CASCADING == 4?" checked":""?>> SOCKS4
			<input type="radio" name="d_CASCADING" onClick="ableCas();" value="5"<?php echo $CASCADING == 5?" checked":""?>> SOCKS5</td></tr>
		<tr><td>Cascading Server:</td><td>
			<input name="d_CAS_SERVER" style="width:200px" value="<?php echo $CAS_SERVER?>"></td></tr>
		<tr><td>Cascading Server Port:</td><td>
			<input name="d_CAS_PORT" style="width:50px" value="<?php echo $CAS_PORT?>"></td></tr>
		<tr><td>Cascading Server Username:</td><td>
			<input name="d_CAS_AUTH_USER" style="width:100px" value="<?php echo $CAS_AUTH_USER?>"></tr>
		<tr><td>Cascading Server Password:</td><td>
			<input name="d_CAS_AUTH_PASS" style="width:100px" value="<?php echo $CAS_AUTH_PASS?>"></tr>
		<tr><td colspan=2>
				<input type="checkbox" name="d_CAS_AUTH_PASSTHROUGH" value="1" style="margin-right:10px"<?php echo $CAS_AUTH_PASSTHROUGH?" checked":""?>> Use HTTP username/password</td></tr>
		</table>
	</div>
   <div class="tab-page">
      <h2 class="tab">Logging</h2>
		<table border=0 cellpadding=0 cellspacing=3 width=100%>
		<tr><th colspan=2><img src="common/info.gif" onmouseover="return overlib(
'<b>Loglevel</b>:<br>- 0 = no logging<br>- 1 = log errors<br>- 2 = log connects/disconnects and warnings<br>- 3 = log data<br>- 4 = debug (not recommended)<br><b>Maximum logfile size</b>: After the logfile exceeds the specified size, it will be renamed to &lt;Logfilename>.old and a new logfile is opened', CAPTION, 'Logfile and Loglevel Settings');" onmouseout="return nd();"> Logfile and Loglevel</th></tr>
		<td>Loglevel:</td><td width=90%><input name="d_LOGLEVEL" style="width:50px" value="<?php echo $LOGLEVEL?>"></td></tr>
		<td>Logfilename:</td><td><input name="d_LOGFILE" style="width:200px" value="<?php echo $LOGFILE?>"></td></tr>
		<td>Maximum logfile size:</td><td><input name="d_MAXLOGSIZE" style="width:100px" value="<?php echo $MAXLOGSIZE?>"> bytes</td></tr>
		</table>
		<a href="<?php echo $_SERVER["SCRIPT_NAME"]?>?d_action=log" target="_new">Click here to open the server log in a new window</a>
   </div>
   <div class="tab-page">
      <h2 class="tab">Miscelaneous</h2>
		<table border=0 cellpadding=0 cellspacing=3 width=100%>
		<tr><th colspan=5><img src="common/info.gif" onmouseover="return overlib(
'Some proxies or HTTP-servers terminate connections after a fixed period of inactivity. To prevent disconnects because of that, we can send linefeeds to the tunnel, keeping it alive. Configure the Tunnel Keepalive here.',CAPTION,'Tunnel Connection Keepalive Settings')" onmouseout="return nd();"> Tunnel Connection Keepalive</th></tr>
		<tr><td colspan=2><input type="checkbox" name="d_TKEEPALIVE_ENABLE" value="1" onClick="ableTKeep()" style="margin-right:10px"<?php echo $TKEEPALIVE_ENABLE?" checked":""?>> Enable Tunnel Keepalive</td>
			<td style="width:40px"></td>
			<td>Keepalive Interval:</td><td><input name="d_TKEEPALIVE_INTERVAL" style="width:50px" value="<?php echo $TKEEPALIVE_INTERVAL?>"> secs</td>
			</tr>
		<tr><th colspan=5><img src="common/info.gif" onmouseover="return overlib(
'The HTTPTunnel script runs in multiple server threads which need to communicate with each other. This is done over sockets, preferably over UNIX domain sockets. This method, however is not available on all systems. TCP is used for fallback.<br><b>Support load balanced servers</b>:<br>must be checked if the script is hosted in a load balanced environment. This will force IPC to be done over TCP and additionally modify the protocol so that executing the script on different servers will be possible.<br><b>UNIX IPC Tempdir</b>:<br>is the directory where the UNIX socket files are created - specify with the the appending slash (e.g. /tmp/)',CAPTION,'Interprocess Communication Settings')" onmouseout="return nd();"> Interprocess Communication</th></tr>
		<tr><td colspan=2><input type="checkbox" name="d_IPC_LOADBALANCE" onClick="ableIPC();" value="1" <?php echo $IPC_LOADBALANCE?" checked":""?>> Support load balanced servers
			<td style="width:40px"></td>
			<td>UNIX IPC Tempdir:</td><td>
			<?php if (in_array("unix", stream_get_transports())) { ?>
				<input name="d_IPC_TMPDIR" style="width:100px" value="<?php echo $IPC_TMPDIR?>">
			<?php } else { ?>
				<input type="hidden" name="d_IPC_TMPDIR" value="<?php echo $IPC_TMPDIR?>">
				<font color=red>not supported by server</font>
			<?php } ?>
			</td></tr>
		<tr><th colspan=5><img src="common/info.gif" onmouseover="return overlib('For additional security, configure intrusion detection and countermeasures here.', CAPTION,'Intrusion Detection Options');" onmouseout="return nd();"> Intrusion Detection and Countermeasures</th></tr>
		<tr><td colspan=5><input type="checkbox" onClick="ableID();" name="d_ID_ENABLE" value="1" style="margin-right:10px"<?php echo $ID_ENABLE?" checked":""?>>Enable Intrusion Detection</td></tr>
		<tr><td colspan=5>Ban client IP after <input name="d_ID_MAXACCESS" style="width:50px" value="<?php echo $ID_MAXACCESS?>"> attempts to access the tunnel server with invalid credentials.</td></tr>
		<tr><td colspan=5>These attempts must have been within an interval of <input name="d_ID_TIMEOUT" style="width:50px" value="<?php echo $ID_TIMEOUT?>"> seconds.</td></tr>
		<tr><td colspan=5>The client IP will stay banned for <input name="d_ID_BANTIMEOUT" style="width:50px" value="<?php echo $ID_BANTIMEOUT?>"> seconds.</td></tr>

		<tr><th colspan=5><img src="common/info.gif" onmouseover="return overlib('Configure encryption options here.', CAPTION,'Encryption Options');" onmouseout="return nd();"> Encryption</th></tr>
		<tr><td colspan=5><input type="checkbox" name="d_ENCRYPTION_FORCE" value="1" style="margin-right:10px"<?php 
		echo ($ENCRYPTION_FORCE && in_array("mcrypt",get_loaded_extensions()) && in_array("openssl",get_loaded_extensions()))?" checked":"";
		echo (in_array("mcrypt",get_loaded_extensions()) && in_array("openssl",get_loaded_extensions()))?"":" disabled";?>>Disallow unencrypted tunnel client connections<?php echo (in_array("mcrypt",get_loaded_extensions()) && in_array("openssl",get_loaded_extensions()))?"":" - <font color=red>Not supported by PHP installation</font>";?></td></tr>
		
		<tr><th colspan=5><img src="common/info.gif" onmouseover="return overlib('<b>Limit access to IPs</b><br>A comma delimited list of IP adresses (netmask can be supplied) that are allowed to access the admin interface, e.g. 127.0.0.1,10.0.0.0/8<br>Leave blank for no restrictions.<br>', CAPTION,'Admin Interface Options');" onmouseout="return nd();"> Admin Interface</th></tr>
		<tr><td colspan=1>Limit access to IPs:</td><td colspan=4><input name="d_ADMIN_IP" style="width:200px" value="<?php echo $ADMIN_IP?>"></td></tr>
		<tr><td colspan=1>Username:</td><td colspan=4><input name="d_ADMIN_AUTH_USER" style="width:100px" value="<?php echo $ADMIN_AUTH_USER?>"></td></tr>
		<tr><td colspan=1>Password:</td><td colspan=4><input name="d_ADMIN_AUTH_PASS" style="width:100px" value="<?php echo $ADMIN_AUTH_PASS?>"></td></tr>
		</table>
	</div>
   <div class="tab-page">
	  <h2 class="tab">About</h2>
		<table border=0 cellpadding=0 cellspacing=3 width=100%>
		<tr><th colspan=2>About HTTPTunnel</th></tr>
		<tr><td style="white-space:normal" valign=top><h1>HTTPTunnel v1.2.1</h1>
&copy;2010 by Sebastian Weber &lt;<a href="mailto:websersebastian@yahoo.de">webersebastian@yahoo.de</a>><br><br>
This software is licensed under the <a href="http://www.gnu.org/copyleft/gpl.html" target="_new">GNU general public license</a>
		</td><td align=right><a href="javascript:showPl()"><img src="common/logo.jpg" style="border:none"></a>
<table id="movie" cellspacing=0 cellpadding=0 style="position:absolute; width:240; visibility:hidden; left:344;top:22;z-index:1000; border:solid #949A9C 1px"><tr><td style="font-size:1px"><a href="javascript:hidePl()"><img src="common/bar.gif" style="margin:0px;padding:0px;border:none"></a></td></tr>
<tr><td height=180><object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" codebase="http://fpdownload.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=8,0,0,0" width="240" height="180" id="3dlogo" align="middle">
<param name="allowScriptAccess" value="sameDomain" />
<param name="movie" value="common/3dlogo.swf" /><param name="quality" value="high" /><param name="bgcolor" value="#ffffff" /><embed src="common/3dlogo.swf" quality="high" bgcolor="#ffffff" width="240" height="180" name="3dlogo" align="middle" allowScriptAccess="sameDomain" type="application/x-shockwave-flash" pluginspage="http://www.macromedia.com/go/getflashplayer" /></object></a></tr><td></table></td></tr>
		</table>
   </div>
   <center>
   <input type="button" value="Save" style="width:100px"
   onClick="if (submitForm()) document.adminform.submit()">
   <input type="button" value="Reset" style="width:100px"
   onClick="document.adminform.reset();ableAuth();showAuth();ableCas();ableTKeep();ableIPC()">
   </center>
</div>
<input type="hidden" name="AUTH_METHOD">
<input type="hidden" name="AUTH_SOURCE">
<input type="hidden" name="AUTH_USER">
<input type="hidden" name="CASCADING">
<input type="hidden" name="CAS_SERVER">
<input type="hidden" name="CAS_PORT">
<input type="hidden" name="CAS_AUTH_USER">
<input type="hidden" name="CAS_AUTH_PASS">
<input type="hidden" name="CAS_AUTH_PASSTHROUGH">
<input type="hidden" name="LOGLEVEL">
<input type="hidden" name="LOGFILE">
<input type="hidden" name="MAXLOGSIZE">
<input type="hidden" name="TKEEPALIVE_ENABLE">
<input type="hidden" name="TKEEPALIVE_INTERVAL">
<input type="hidden" name="IPC_LOADBALANCE">
<input type="hidden" name="IPC_TMPDIR">
<input type="hidden" name="ID_ENABLE">
<input type="hidden" name="ID_TIMEOUT">
<input type="hidden" name="ID_BANTIMEOUT">
<input type="hidden" name="ID_MAXACCESS">
<input type="hidden" name="ENCRYPTION_FORCE">
<input type="hidden" name="ADMIN_IP">
<input type="hidden" name="ADMIN_AUTH_USER">
<input type="hidden" name="ADMIN_AUTH_PASS">
<input type="hidden" name="LDAP_SERVER">
<input type="hidden" name="LDAP_PORT">
<input type="hidden" name="LDAP_USER">
<input type="hidden" name="LDAP_PASS">
<input type="hidden" name="LDAP_BASE">
<input type="hidden" name="LDAP_FILTER">
<input type="hidden" name="MYSQL_SERVER">
<input type="hidden" name="MYSQL_PORT">
<input type="hidden" name="MYSQL_USER">
<input type="hidden" name="MYSQL_PASS">
<input type="hidden" name="MYSQL_DB">
<input type="hidden" name="MYSQL_QUERY">
<input type="hidden" name="SEC_IP">
</form>
<script>setupAllTabs();</script>
</body>
</html>
