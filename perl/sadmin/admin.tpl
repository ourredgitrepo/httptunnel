<html>
<head>
<title>HTTPTunnel Server Administration</title>
<link rel="shortcut icon" href="server.ico" type="image/x-icon" />
<link type="text/css" rel="StyleSheet" href="tab.css" />
<script type="text/javascript" src="tabpane.js"></script>
<script type="text/javascript" src="overlib_mini.js"></script>
<script>
	function initAddUser() {
		var dialog=window.open('','user','height=130,width=385,dependent=yes,directories=no,location=no,menubar=no,resizable=yes,scrollbars=no,status=no,toolbar=no');
		dialog.document.write(getUserHTML('Add','','',-1));
		dialog.document.close();
	}
	function initModUser() {
		var sel=document.adminform.d_AUTH_USER;
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

	function ableKeep() {
		var i=!document.adminform.d_KEEPALIVE_ENABLE.checked;
		document.adminform.d_KEEPALIVE_INTERVAL.disabled=i;
		document.adminform.d_KEEPALIVE_SERVER.disabled=i;
		document.adminform.d_KEEPALIVE_PORT.disabled=i;
	}

	function ableTKeep() {
		var i=!document.adminform.d_TKEEPALIVE_ENABLE.checked;
		document.adminform.d_TKEEPALIVE_INTERVAL.disabled=i;
	}

	function getUserHTML (action,user,pass,idx) {
		var ret='\
		<head><title>'+action+' User</title>\n\
		<link type="text/css" rel="StyleSheet" href="tab.css" />\n\
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
		trim("d_PORT");trim("d_IF");trim("d_SEC_IP");
		trim("d_LDAP_SERVER");trim("d_LDAP_PORT");trim("d_MYSQL_SERVER");trim("d_MYSQL_PORT");
		trim("d_MYSQL_USER");trim("d_MYSQL_DB");trim("d_SEC_IP");

		if (isNaN(parseInt(f.d_PORT.value)) || parseInt(f.d_PORT.value)<=0)
			push(errors,"Please specify a numeric listen port","d_PORT");
		if (f.d_IF.value && !f.d_IF.value.match(/^\d+\.\d+\.\d+\.\d+$/))
			push(errors,"Interface must be left blank or in the form \"x.x.x.x\"","d_IF");
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
		trim("d_LOGLEVEL");trim("d_MAXLOGSIZE");trim("d_MAXLOGS");

		if (isNaN(parseInt(f.d_LOGLEVEL.value)) || parseInt(f.d_LOGLEVEL.value)<0)
			push(errors,"Please specify a numeric loglevel","d_LOGLEVEL");
		if (parseInt(f.d_LOGLEVEL.value)>0) {
			if (!f.d_LOGFILE.value) push(errors,"Please specify a log filename","d_LOGFILE");
			if (isNaN(parseInt(f.d_MAXLOGSIZE.value)) || parseInt(f.d_MAXLOGSIZE.value)<=0)
				push(errors,"Please specify a numeric maximum logfile size","d_MAXLOGSIZE");
			if (parseInt(f.d_MAXLOGSIZE.value)<100000)
				push(warnings,"Maximum logfile size should be at least 100 kbytes","");
			if (f.d_MAXLOGS.value && (isNaN(parseInt(f.d_MAXLOGSIZE.value)) || parseInt(f.d_MAXLOGSIZE.value)<0))
				push(errors,"Please specify a numeric number of logfiles to keep or leave empty","d_MAXLOGS");
		}

		// check tab4 *****************
		trim("d_KEEPALIVE_SERVER");trim("d_KEEPALIVE_PORT");trim("d_KEEPALIVE_INTERVAL");
		trim("d_TKEEPALIVE_INTERVAL");trim("d_THREADS");trim("d_MAXTHREADS");

		if (getValue("d_KEEPALIVE_ENABLE")) {
			if (!f.d_KEEPALIVE_SERVER.value) push(errors,"Please specify a keepalive server name","d_KEEPALIVE_SERVER");
			if (isNaN(parseInt(f.d_KEEPALIVE_PORT.value)) || parseInt(f.d_KEEPALIVE_PORT.value)<=0)
				push(errors,"Please specify a numeric keepalive server port number","d_KEEPALIVE_PORT");
			if (isNaN(parseInt(f.d_KEEPALIVE_INTERVAL.value)) || parseInt(f.d_KEEPALIVE_INTERVAL.value)<=0)
				push(errors,"Please specify a numeric keepalive interval in seconds","d_KEEPALIVE_INTERVAL");
		}

		if (getValue("d_TKEEPALIVE_ENABLE") && (isNaN(parseInt(f.d_TKEEPALIVE_INTERVAL.value)) || parseInt(f.d_TKEEPALIVE_INTERVAL.value)<=0))
			push(errors,"Please specify a numeric tunnel keepalive interval in seconds","d_TKEEPALIVE_INTERVAL");

		if (isNaN(parseInt(f.d_THREADS.value)) || parseInt(f.d_THREADS.value)<0)
			push(errors,"Please specify a constant number of worker threads","d_THREADS");
		if (isNaN(parseInt(f.d_MAXTHREADS.value)) || parseInt(f.d_MAXTHREADS.value)<0)
			push(errors,"Please specify a maximum number of simultaneous connections","d_MAXTHREADS");
		else if (!isNaN(parseInt(f.d_MAXTHREADS.value)) && parseInt(f.d_MAXTHREADS.value)>0 && parseInt(f.d_MAXTHREADS.value)<parseInt(f.d_THREADS.value))
			push(errors,"The maximum number of simultaneous connections must be greater or equal to the constant number of worker threads","d_MAXTHREADS");
		
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
		f.PORT.value=getValue('d_PORT');
		f.IF.value=getValue('d_IF');
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
		f.MAXLOGS.value=getValue('d_MAXLOGS');
		f.KEEPALIVE_ENABLE.value=getValue('d_KEEPALIVE_ENABLE');
		f.KEEPALIVE_SERVER.value=getValue('d_KEEPALIVE_SERVER');
		f.KEEPALIVE_PORT.value=getValue('d_KEEPALIVE_PORT');
		f.KEEPALIVE_INTERVAL.value=getValue('d_KEEPALIVE_INTERVAL');
		f.TKEEPALIVE_ENABLE.value=getValue('d_TKEEPALIVE_ENABLE');
		f.TKEEPALIVE_INTERVAL.value=getValue('d_TKEEPALIVE_INTERVAL');
		f.THREADS.value=getValue('d_THREADS');
		f.MAXTHREADS.value=getValue('d_MAXTHREADS');
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
		"Would you "+(warnings.length?"still ":"")+"like to save your changes?\n\n"+
		"Please note: Saving your changes will cause the HTTPTunnel server\n"+
		"to be restarted, thereby disconnecting all currently connected\n"+
		"clients");
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
<body style="background:ThreeDFace" onLoad="ableAuth();showAuth();ableCas();ableKeep();ableTKeep();ableID();">
<div id="overDiv" style="position:absolute; visibility:hidden; z-index:1000;"></div>
<form name="adminform" action="admin_save.tpl?d_action=save" method="POST">
<div class="tab-pane">
<h1><img src="cpanel.png"> HTTPTunnel Standalone Server Administration</h1>
<%if @globalstatus>0%>
	<table class="warning">
	<tr><td colspan=2><b>HTTPTunnel server startup messages:</b></td></tr>
	<%eval $i=-1%>
	<%loop%>
	    <%if ++$i>=@globalstatus%>
	        <%break%>
	    <%end%>
		<tr><td> - </td><td><%$globalstatus[$i]%></td></tr>
	<%end%>
	</table>
<%end%>
<div class="tab-pane" style="width: 600">
   <div class="tab-page">
      <h2 class="tab">Tunnel Server</h2>
		<table border=0 cellpadding=0 cellspacing=3 width=100%>
		<tr><th colspan=2><img src="info.gif" onmouseover="return overlib(
'<b>Port to listen on</b>:<br>Which port should the server listen on?<br><b>Listen on interface</b>:<br>Specify the interface address the server should listen on. Leave blank for all.<br><b>Authentication Method</b>:<br>Does the server require authentication? Currently, only basic authentication is supported', CAPTION, 'HTTPTunnel Server Settings');" onmouseout="return nd();"> HTTPTunnel Server Settings</th></tr>
		<tr><td valign=top>
			<table border=0 cellpadding=0 cellspacing=0 width=100%>
			<tr><td>Port to listen on:</td>
				<td style="text-align:right"><input style="width:50px;margin-left:10px" name="d_PORT" value="<%$cfg->{PORT}%>"></td></tr>
			<tr><td>Listen on interface:</td>
				<td style="text-align:right"><input style="width:100px;margin-left:10px" name="d_IF" value="<%$cfg->{IF}%>"></td></tr>
			<tr><td style="white-space:normal;padding-bottom:3px">HTTP Authentication Method:<br>&nbsp;</td>
				<td style="padding-bottom:3px">
				<input type="radio" name="d_AUTH_METHOD" onClick="ableAuth();" value="none"<%$cfg->{AUTH_METHOD} eq "none"?" checked":""%>> None<br>
				<input type="radio" name="d_AUTH_METHOD" onClick="ableAuth();" value="basic"<%$cfg->{AUTH_METHOD} eq "basic"?" checked":""%>> Basic</td></tr>
			<tr><th colspan=2>Authentication Source</th></tr>
			<tr><td colspan=2>
				<input type="radio" name="d_AUTH_SOURCE" style="vertical-align:middle;margin-right:10px" onClick="showAuth()" value="1"<%$cfg->{AUTH_SOURCE}==1?" checked":""%>>Fixed User list<br>
				<input type="radio" name="d_AUTH_SOURCE" style="vertical-align:middle;margin-right:10px" onClick="showAuth()" value="2"<%($cfg->{MOD_LDAP_AVAILABLE} && $cfg->{AUTH_SOURCE}==2)?" checked":""%><%$cfg->{MOD_LDAP_AVAILABLE}?"":" class='noinp'"%>>LDAP<%$cfg->{MOD_LDAP_AVAILABLE}?"":" - <font color=red>Module not installed</font>"%><br>
				<input type="radio" name="d_AUTH_SOURCE" style="vertical-align:middle;margin-right:10px" onClick="showAuth()" value="3"<%($cfg->{MOD_MYSQL_AVAILABLE} && $cfg->{AUTH_SOURCE}==3)?" checked":""%><%$cfg->{MOD_MYSQL_AVAILABLE}?"":" class='noinp'"%>>MySQL<%$cfg->{MOD_MYSQL_AVAILABLE}?"":" - <font color=red>Module not installed</font>"%>
			</td></tr></table>
		</td><td valign=top>
		<div id="authtab" class="tab-pane" style="width: 350">
			<div class="tab-page">
			<h2 class="tab">User List</h2>
			<table border=0 cellpadding=0 cellspacing=0 width="100%">
				<tr><th>Fixed User List Authentication Settings</th></tr>
				<tr><td style="padding-top:3px">
				<select name="d_AUTH_USER" size=6 style="width:200;float:left">
<%eval $i=-1%>
<%eval @pm=split(/\n/,$cfg->{AUTH_USER})%>
<%loop%>
    <%if ++$i>=@pm || $pm[$i] eq ""%>
        <%break%>
    <%end%>
	<%eval @pm1=split(/:/,$pm[$i])%>
		<option value="<%$pm1[0]%>"><%$pm1[0]%>:<%$pm1[1]%></option>
<%end%>
				</select>
				<input type="button" value="Add" name="d_USADD" onClick="initAddUser()" style="width:70"><br>
				<input type="button" value="Remove" name="d_USDEL" onClick="removeSel('d_AUTH_USER')" style="width:70"><br>
				<input type="button" value="Modify" name="d_USMOD" onClick="initModUser()" style="width:70"><br>
				</td></tr></table>
			</div>
			<div class="tab-page">
			<h2 class="tab">LDAP</h2>
			<table border=0 cellpadding=0 cellspacing=0 width=100%>
				<tr><th colspan=2><img src="info.gif" onmouseover="return overlib(
'<b>Filter</b>:<br>This is the query that is sent to the LDAP server. If the query returns any entries, authentication is successful. The character sequences \'\\u\' and \'\\p\' are replaced by the username and password provided by the HTTP client. Example of a filter:<br>(&(uid=\\u) (pass=\\p))', CAPTION, 'LDAP Authentication Settings');" onmouseout="return nd();"> LDAP Authentication</th></tr>
				<tr><td style="padding-top:3px">Server:</td><td style="padding-top:3px"><input name="d_LDAP_SERVER" style="width:200px" value="<%$cfg->{LDAP_SERVER}%>"></td></tr>
				<tr><td>Port:</td><td><input name="d_LDAP_PORT" style="width:50px" value="<%$cfg->{LDAP_PORT}%>"> (standard: 389)</td></tr>
				<tr><td>Username / Password:</td><td>
					<input name="d_LDAP_USER" style="width:98px" value="<%$cfg->{LDAP_USER}%>">
					<input name="d_LDAP_PASS" style="width:98px" value="<%$cfg->{LDAP_PASS}%>"></td></tr>
				<tr><td>Base DN:</td><td><input name="d_LDAP_BASE" style="width:200px" value="<%$cfg->{LDAP_BASE}%>"></td></tr>
				<tr><td>Filter:</td><td><input name="d_LDAP_FILTER" style="width:200px" value="<%$cfg->{LDAP_FILTER}%>"></td></tr>
				</table>
			</div>
			<div class="tab-page">
			<h2 class="tab">MySQL</h2>
			<table border=0 cellpadding=0 cellspacing=0 width=100%>
				<tr><th colspan=2><img src="info.gif" onmouseover="return overlib(
'<b>Query</b>:<br>This is the query that is sent to the MySQL server. If the query returns any entries, authentication is successful. The character sequences \'\\u\' and \'\\p\' are replaced by the username and password provided by the HTTP client. Example of a query:<br>SELECT * FROM users WHERE uid=\'\\u\' AND pass=PASSWORD(\'\\p\')', CAPTION, 'MySQL Authentication Settings');" onmouseout="return nd();"> MySQL Authentication</th></tr>
				<tr><td style="padding-top:3px">Server:</td><td style="padding-top:3px"><input name="d_MYSQL_SERVER" style="width:200px" value="<%$cfg->{MYSQL_SERVER}%>"></td></tr>
				<tr><td>Port:</td><td><input name="d_MYSQL_PORT" style="width:50px" value="<%$cfg->{MYSQL_PORT}%>"> (standard: 3306)</td></tr>
				<tr><td>Username / Password:</td><td>
					<input name="d_MYSQL_USER" style="width:98px" value="<%$cfg->{MYSQL_USER}%>">
					<input name="d_MYSQL_PASS" style="width:98px" value="<%$cfg->{MYSQL_PASS}%>"></td></tr>
				<tr><td>Database:</td><td><input name="d_MYSQL_DB" style="width:200px" value="<%$cfg->{MYSQL_DB}%>"></td></tr>
				<tr><td>Query:</td><td><input name="d_MYSQL_QUERY" style="width:200px" value="<%$cfg->{MYSQL_QUERY}%>"></td></tr>
				</table>
			</div>
		</div>
		</td></tr>
		<tr><th colspan=2><img src="info.gif" onmouseover="return overlib(
'<b>Limit access to IPs</b><br>A comma delimited list of IP adresses (netmask can be supplied) that are allowed to access the HTTPTunnel server, e.g. 127.0.0.1,10.0.0.0/8<br>Leave blank for no restrictions.<br>', CAPTION, 'Security Settings');" onmouseout="return nd();"> Security</th></tr>
		<tr><td colspan=2>Limit access to IPs: <input name="d_SEC_IP" style="width:200px" value="<%$cfg->{SEC_IP}%>"></td></tr>
		</table>
   </div>
	<div class="tab-page">
		<h2 class="tab">Cascading</h2>
		<table border=0 cellpadding=0 cellspacing=3 width=100%>
		<tr><th colspan=2><img src="info.gif" onmouseover="return overlib(
'Connections to the remote hosts can be made over a SOCKS4 or SOCKS5 proxy. Configure the SOCKS cascading here', CAPTION, 'SOCKS Cascading Settings');" onmouseout="return nd();"> SOCKS Cascading</th></tr>
		<tr><td width=30%>Cascading enabled:</td><td>
			<input type="radio" name="d_CASCADING" onClick="ableCas();" value="0"<%$cfg->{CASCADING} eq "0"?" checked":""%>> disabled
			<input type="radio" name="d_CASCADING" onClick="ableCas();" value="4"<%$cfg->{CASCADING} eq "4"?" checked":""%>> SOCKS4
			<input type="radio" name="d_CASCADING" onClick="ableCas();" value="5"<%$cfg->{CASCADING} eq "5"?" checked":""%>> SOCKS5</td></tr>
		<tr><td>Cascading Server:</td><td>
			<input name="d_CAS_SERVER" style="width:200px" value="<%$cfg->{CAS_SERVER}%>"></td></tr>
		<tr><td>Cascading Server Port:</td><td>
			<input name="d_CAS_PORT" style="width:50px" value="<%$cfg->{CAS_PORT}%>"></td></tr>
		<tr><td>Cascading Server Username:</td><td>
			<input name="d_CAS_AUTH_USER" style="width:100px" value="<%$cfg->{CAS_AUTH_USER}%>"></tr>
		<tr><td>Cascading Server Password:</td><td>
			<input name="d_CAS_AUTH_PASS" style="width:100px" value="<%$cfg->{CAS_AUTH_PASS}%>"></tr>
		<tr><td colspan=2>
				<input type="checkbox" name="d_CAS_AUTH_PASSTHROUGH" value="1" style="margin-right:10px"<%$cfg->{CAS_AUTH_PASSTHROUGH} eq "1"?" checked":""%>> Use HTTP username/password</td></tr>
		</table>
	</div>
   <div class="tab-page">
      <h2 class="tab">Logging</h2>
		<table border=0 cellpadding=0 cellspacing=3 width=100%>
		<tr><th colspan=2><img src="info.gif" onmouseover="return overlib(
'<b>Loglevel</b>:<br>- 0 = no logging<br>- 1 = log errors<br>- 2 = log connects/disconnects and warnings<br>- 3 = log data<br>- 4 = debug (not recommended)<br><b>Maximum logfile size</b>: After the logfile exceeds the specified size, it will be renamed, packed (if the appropriate modules are installed) and a new logfile is opened<br><b>Maximum number of logfiles to keep.</b><br>The maximum number of old logfiles to keep. Leave empty for unlimited.', CAPTION, 'Logfile and Loglevel Settings');" onmouseout="return nd();"> Logfile and Loglevel</th></tr>
		<td>Loglevel:</td><td width=90%><input name="d_LOGLEVEL" style="width:50px" value="<%$cfg->{LOGLEVEL}%>"></td></tr>
		<td>Logfilename:</td><td><input name="d_LOGFILE" style="width:200px" value="<%$cfg->{LOGFILE}%>"></td></tr>
		<td>Maximum logfile size:</td><td><input name="d_MAXLOGSIZE" style="width:100px" value="<%$cfg->{MAXLOGSIZE}%>"> bytes</td></tr>
		<td>Maximum number of logfiles to keep:</td><td><input name="d_MAXLOGS" style="width:50px" value="<%$cfg->{MAXLOGS}%>"></td></tr>
		</table>
   </div>
   <div class="tab-page">
      <h2 class="tab">Miscelaneous</h2>
		<table border=0 cellpadding=0 cellspacing=3 width=100%>
		<tr><th colspan=5><img src="info.gif" onmouseover="return overlib(
'If you want to run your server on a dialup connection which gets disconnected after a certain period of inactivity, you need to keep the connection alive by connecting to a server every now and then. Configure the Internet Connection Keepalive here.',CAPTION,'Internet Connection Keepalive Settings')" onmouseout="return nd();"> Internet Connection Keepalive</th></tr>
		<tr><td colspan=5>
			<input type="checkbox" name="d_KEEPALIVE_ENABLE" value="1" onClick="ableKeep()" style="margin-right:10px"<%$cfg->{KEEPALIVE_ENABLE} eq "1"?" checked":""%>> Enable Internet Keepalive</td></tr>
		<tr><td>Keepalive Server:</td><td><input name="d_KEEPALIVE_SERVER" style="width:150px" value="<%$cfg->{KEEPALIVE_SERVER}%>"></td>
			<td style="width:40px"></td>
			<td>Keepalive Interval:</td><td><input name="d_KEEPALIVE_INTERVAL" style="width:50px" value="<%$cfg->{KEEPALIVE_INTERVAL}%>"> secs</td>
			</tr>
		<tr><td>Keepalive Server Port:</td><td><input name="d_KEEPALIVE_PORT" style="width:50px" value="<%$cfg->{KEEPALIVE_PORT}%>"></td><td colspan=3>&nbsp;</td></tr>
		<tr><th colspan=5><img src="info.gif" onmouseover="return overlib(
'Some proxies terminate connections after a fixed period of inactivity. To prevent disconnects because of that, we can send linefeeds to the tunnel, keeping it alive. Configure the Tunnel Keepalive here.',CAPTION,'Tunnel Connection Keepalive Settings')" onmouseout="return nd();"> Tunnel Connection Keepalive</th></tr>
		<tr><td colspan=2><input type="checkbox" name="d_TKEEPALIVE_ENABLE" value="1" onClick="ableTKeep()" style="margin-right:10px"<%$cfg->{TKEEPALIVE_ENABLE} eq "1"?" checked":""%>> Enable Tunnel Keepalive</td>
			<td style="width:40px"></td>
			<td>Keepalive Interval:</td><td><input name="d_TKEEPALIVE_INTERVAL" style="width:50px" value="<%$cfg->{TKEEPALIVE_INTERVAL}%>"> secs</td>
			</tr>
		<tr><th colspan=5><img src="info.gif" onmouseover="return overlib(
'<b>Constant number of worker threads</b><br>At program startup, the HTTPTunnel server initializes the specified number of permanent threads that listen for incoming connections.<br><b>Maximum number of simultaneous connections</b><br>defines the maximum number of simultaneous HTTP connections this HTTPTunnel server can process. <b>Please note</b>: This number must be greater or equal to the constant number of worker threads of 0 for unlimited!', CAPTION,'Scalability Options');" onmouseout="return nd();"> Scalability</th></tr>
		<tr><td colspan=2>Constant number of worker threads:</td><td colspan=3><input name="d_THREADS" style="width:50px" value="<%$cfg->{THREADS}%>"></td></tr>
		<tr><td colspan=2>Maximum number of simultaneous connections:</td><td colspan=3><input name="d_MAXTHREADS" style="width:50px" value="<%$cfg->{MAXTHREADS}%>"></td></tr>

		<tr><th colspan=5><img src="info.gif" onmouseover="return overlib('For additional security, configure intrusion detection and countermeasures here.', CAPTION,'Intrusion Detection Options');" onmouseout="return nd();"> Intrusion Detection and Countermeasures</th></tr>
		<tr><td colspan=5><input type="checkbox" onClick="ableID();" name="d_ID_ENABLE" value="1" style="margin-right:10px"<%$cfg->{ID_ENABLE}?" checked":""%>>Enable Intrusion Detection</td></tr>
		<tr><td colspan=5>Ban client IP after <input name="d_ID_MAXACCESS" style="width:50px" value="<%$cfg->{ID_MAXACCESS}%>"> attempts to access the tunnel server with invalid credentials.</td></tr>
		<tr><td colspan=5>These attempts must have been within an interval of <input name="d_ID_TIMEOUT" style="width:50px" value="<%$cfg->{ID_TIMEOUT}%>"> seconds.</td></tr>
		<tr><td colspan=5>The client IP will stay banned for <input name="d_ID_BANTIMEOUT" style="width:50px" value="<%$cfg->{ID_BANTIMEOUT}%>"> seconds.</td></tr>

		<tr><th colspan=5><img src="info.gif" onmouseover="return overlib('Configure encryption options here.', CAPTION,'Encryption Options');" onmouseout="return nd();"> Encryption</th></tr>
		<tr><td colspan=5><input type="checkbox" name="d_ENCRYPTION_FORCE" value="1" style="margin-right:10px"<%($cfg->{ENCRYPTION_FORCE} && $cfg->{MOD_RSA_AVAILABLE})?" checked":""%><%$cfg->{MOD_RSA_AVAILABLE}?"":" disabled"%>>Disallow unencrypted tunnel client connections<%$cfg->{MOD_RSA_AVAILABLE}?"":" - <font color=red>Module not installed</font>"%></td></tr>

		<tr><th colspan=5><img src="info.gif" onmouseover="return overlib('<b>Limit access to IPs</b><br>A comma delimited list of IP adresses (netmask can be supplied) that are allowed to access the admin interface, e.g. 127.0.0.1,10.0.0.0/8<br>Leave blank for no restrictions.<br>', CAPTION,'Admin Interface Options');" onmouseout="return nd();"> Admin Interface</th></tr>
		<tr><td colspan=1>Limit access to IPs:</td><td colspan=4><input name="d_ADMIN_IP" style="width:200px" value="<%$cfg->{ADMIN_IP}%>"></td></tr>
		<tr><td colspan=1>Username:</td><td colspan=4><input name="d_ADMIN_AUTH_USER" style="width:100px" value="<%$cfg->{ADMIN_AUTH_USER}%>"></td></tr>
		<tr><td colspan=1>Password:</td><td colspan=4><input name="d_ADMIN_AUTH_PASS" style="width:100px" value="<%$cfg->{ADMIN_AUTH_PASS}%>"></td></tr>
		</table>
	</div>
   <div class="tab-page">
	  <h2 class="tab">Status</h2>
		<table border=0 cellpadding=0 cellspacing=3 width=100%>
		<tr><th><img src="refresh.gif" onmouseover="return overlib(
'Click here to refresh the status display');" onmouseout="return nd();" onClick="refreshStatus()"> Current HTTPTunnel Server Status</th></tr>
		<tr><td>
		<a href="stats.tpl" target="_new">Click here to open the current server status in a new window</a><br>
		<a href="log.tpl" target="_new">Click here to open the server log in a new window</a><br>
		<iframe name="stats" width=100% height=400 src="stats.tpl" border=0 frameborder=0></iframe>
		</td></tr>
		</table>
   </div>
   <div class="tab-page">
	  <h2 class="tab">About</h2>
		<table border=0 cellpadding=0 cellspacing=3 width=100%>
		<tr><th colspan=2>About HTTPTunnel</th></tr>
		<tr><td style="white-space:normal" valign=top width="100%"><h1>HTTPTunnel v<% REL_VERSION %></h1>
&copy;<% REL_YEAR %> by Sebastian Weber &lt;<a href="mailto:websersebastian@yahoo.de">webersebastian@yahoo.de</a>><br><br>
This software is licensed under the <a href="http://www.gnu.org/copyleft/gpl.html" target="_new">GNU general public license</a>
		</td><td align=right><a href="javascript:showPl()"><img src="logo.jpg" style="border:none"></a>
<table id="movie" cellspacing=0 cellpadding=0 style="position:absolute; width:240; visibility:hidden; left:344;top:22;z-index:1000; border:solid #949A9C 1px"><tr><td style="font-size:1px"><a href="javascript:hidePl()"><img src="bar.gif" style="margin:0px;padding:0px;border:none"></a></td></tr>
<tr><td height=180><object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" codebase="http://fpdownload.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=8,0,0,0" width="240" height="180" id="3dlogo" align="middle">
<param name="allowScriptAccess" value="sameDomain" />
<param name="movie" value="3dlogo.swf" /><param name="quality" value="high" /><param name="bgcolor" value="#ffffff" /><embed src="3dlogo.swf" quality="high" bgcolor="#ffffff" width="240" height="180" name="3dlogo" align="middle" allowScriptAccess="sameDomain" type="application/x-shockwave-flash" pluginspage="http://www.macromedia.com/go/getflashplayer" /></object></a></tr><td></table></td></tr>
		</table>
   </div>
   <center>
   <input type="button" value="Save" style="width:100px"
   onClick="if (submitForm()) document.adminform.submit()">
   <input type="button" value="Reset" style="width:100px"
   onClick="document.adminform.reset();ableAuth();showAuth();ableCas();ableKeep();ableTKeep()">
   </center>
</div>
<input type="hidden" name="PORT">
<input type="hidden" name="IF">
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
<input type="hidden" name="MAXLOGS">
<input type="hidden" name="KEEPALIVE_ENABLE">
<input type="hidden" name="KEEPALIVE_SERVER">
<input type="hidden" name="KEEPALIVE_PORT">
<input type="hidden" name="KEEPALIVE_INTERVAL">
<input type="hidden" name="TKEEPALIVE_ENABLE">
<input type="hidden" name="TKEEPALIVE_INTERVAL">
<input type="hidden" name="THREADS">
<input type="hidden" name="MAXTHREADS">
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
