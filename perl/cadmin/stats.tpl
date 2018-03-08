<html>
<head>
<title>HTTPTunnel Client Status</title>
<%if $params->{ups}%>
<META http-equiv="refresh" content="<%$params->{ups}%>; URL=stats.tpl?ups=<%$params->{ups}%>">
<%end%>
<META HTTP-EQUIV="Expires" CONTENT="Mon, 06 Jan 1990 00:00:01 GMT">
<link type="text/css" rel="StyleSheet" href="tab.css" />
</head>
<body style="background-color:#FCFCFE; margin:3px">
<table border=1 width=100% cellspacing=0 cellpadding=1><tr><th>Task ID</th><th>Type</th><th>Status</th></tr>
<%eval $i=-1%>
<%eval @pm=sort {$a <=> $b} keys(%$status)%>
<%loop%>
    <%if ++$i>=@pm%>
        <%break%>
    <%end%>
	<tr><td><%$pm[$i]%></td><td><%$type->{$pm[$i]}%></td><td><%$status->{$pm[$i]}%></td></tr>
<%end%>
</table>
<table><tr><td><br><form name="upf" action="stats.tpl"><input size="2" name="ups" value="<%$params->{ups}%>"> Automatic update interval <input type="submit" value="Update" style="visibility:hidden"></form></td></tr></table>
</body>
</html>