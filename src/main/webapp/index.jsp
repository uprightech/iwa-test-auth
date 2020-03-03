<%@ page import="org.gluu.test.spnego.SpnegoAuthenticatedUser" %>

<%
  SpnegoAuthenticatedUser authenticated_user = (SpnegoAuthenticatedUser) session.getAttribute("authenticated_user");
%>
<html>
<body>
<h2>Hello <%= authenticated_user.getUsername() %> . You got authenticated !</h2>
</body>
</html>
