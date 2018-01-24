package client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.json.JSONObject;

import controls.domains.Domain;
import controls.domains.DomainController;
import util.AuthProperties;
import util.HttpConnection;
import util.JWT;

public class COPEL_SCADA 
{
	static {
	    javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
	    new javax.net.ssl.HostnameVerifier(){
 
	        public boolean verify(String hostname,
	                javax.net.ssl.SSLSession sslSession) {
	            return true;
	        }
	    });
	}
	public static void init()
	{
		String domainName = "copel";
		DomainController domains = DomainController.getInstance();
		Domain d = domains.getDomain(domainName);
		prop = AuthProperties.init(d);
	}
	public static AuthProperties prop;
	
	
	public static String Authenticate(String user, String password) throws Exception
	{		
		String clientID = prop.getConsumerKey();
		String clientPWD = prop.getConsumerSecret();
		URL obj = new URL(prop.getTokenEndpoint());
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional default is GET
		con.setRequestMethod("POST");

		//add request header
		//con.setRequestProperty("User-Agent", "Mozilla/5.0");
		String encoded = Base64.getEncoder().encodeToString((clientID+":"+clientPWD).getBytes(StandardCharsets.UTF_8));
		con.setRequestProperty("Authorization", "Basic " + encoded);
		con.setRequestProperty("Content-Type","application/x-www-form-urlencoded;charset=UTF-8"); 
		con.setDoOutput(true);
		
		String str =  "grant_type=password&username=" + user + "&password=" + password;
		byte[] outputInBytes = str.getBytes("UTF-8");
		OutputStream os = con.getOutputStream();
		os.write( outputInBytes );    
		os.close();

		BufferedReader in = new BufferedReader(
		        new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		String jsonString = response.toString();
		JSONObject jObject = new JSONObject(jsonString);		
		//print result
		return jObject.getString("access_token");
	}
	
	public static String getCode(String authenticationCode) throws Exception
	{
		String clientID = prop.getConsumerKey();
		String callBackURL = prop.getCallBackURL();
		URL obj = new URL(prop.getAuthzEndpoint());
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional default is GET
		con.setRequestMethod("POST");

		//add request header
		con.setRequestProperty("Authorization", "Bearer " + authenticationCode);
		con.setRequestProperty("Content-Type","application/x-www-form-urlencoded;charset=UTF-8"); 
		con.setDoOutput(true);
		con.setInstanceFollowRedirects(false);
		
		String str =  "response_type=code&client_id=" + clientID + "&redirect_uri=" + callBackURL + "&scope=openid";
		byte[] outputInBytes = str.getBytes("UTF-8");
		OutputStream os = con.getOutputStream();
		os.write( outputInBytes );    
		os.close();
				
		BufferedReader in = new BufferedReader(
		        new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		//print result
		String location = con.getHeaderField("Location");
		System.out.println(location);
		URI uri = new URI(location);		
		String code = HttpConnection.getParameter(uri.getQuery(), "code");		
		return code;
	}
	
	public static String getTokens(String code) throws Exception
	{
		String clientID = prop.getConsumerKey();
		String clientPWD = prop.getConsumerSecret();
		String callBackURL = prop.getCallBackURL();
		URL obj = new URL(prop.getTokenEndpoint());
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional default is GET
		con.setRequestMethod("POST");

		//add request header
		//con.setRequestProperty("User-Agent", "Mozilla/5.0");
		String encoded = Base64.getEncoder().encodeToString((clientID+":"+clientPWD).getBytes(StandardCharsets.UTF_8));  //Java 8
		con.setRequestProperty("Authorization", "Basic "+encoded);
		con.setRequestProperty("Content-Type","application/x-www-form-urlencoded;charset=UTF-8"); 
		con.setDoOutput(true);
		
		String str =  "grant_type=authorization_code&client_id=" + clientID + "&redirect_uri=" + callBackURL + "&code=" + code + "&scope=openid";
		byte[] outputInBytes = str.getBytes("UTF-8");
		OutputStream os = con.getOutputStream();
		os.write( outputInBytes );    
		os.close();

		BufferedReader in = new BufferedReader(
		        new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		//print result
		return response.toString();
	}
	
	public static String validarToken(String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "validate-token?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String getRoles(String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String getUserInfo(String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "user-information?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String getActivateRoles(String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/activated?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String addActivateRoles(String token, String roleID) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/activated?accessToken=" + token + "&role=" + roleID;
		String response = HttpConnection.sendPost(url);
		return response;
	}
	
	public static String dropActivateRoles(String token, String roleID) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/activated?accessToken=" + token + "&role=" + roleID;
		String response = HttpConnection.sendDelete(url);
		return response;
	}
	
	public static String getConstraints(String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/constraints?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String addConstraints(String token, String roleA, String roleB) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/constraints?accessToken=" + token + "&roleA=" + roleA + "&roleB=" + roleB;
		String response = HttpConnection.sendPost(url);
		return response;
	}
	
	public static String dropConstraints(String token, String roleA, String roleB) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/constraints?accessToken=" + token + "&roleA=" + roleA + "&roleB=" + roleB;
		String response = HttpConnection.sendDelete(url);
		return response;
	}
	
	public static String requestAccess(String token, String resource, String action) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "access-control?accessToken=" + token + "&resource=" + resource + "&action=" + action;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String exportRole(String token, String role, String domain) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "wallet?accessToken=" + token + "&role=" + role+ "&domain=" + domain;
		String response = HttpConnection.sendPost(url);
		return response;
	}	
	
	public static String getExportedRoles(String token, String domain) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "wallet?accessToken=" + token + "&domain=" + domain;
		String response = HttpConnection.sendGet(url);
		return response;
	}

	public static String getTrustedDomains(String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "domain?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static void main(String[] args) throws Exception 
	{
		init();
		String authenticationCode = Authenticate("vilmar@copel.com", "vilmar");
		String code = getCode(authenticationCode);
		String tokens = getTokens(code);
		JSONObject jTokens = new JSONObject(tokens);	
		String accessToken = jTokens.getString("access_token");
		String idToken = jTokens.getString("id_token");
		
		System.out.println("acessToken: " + accessToken);
		System.out.println("idToken: " + idToken);

		JWT.processToken(idToken);
						
		//TESTAR A PESQUISA DE PAPÉIS
		System.out.println("Userinfo: \t" + getUserInfo(accessToken));
		System.out.println(getRoles(accessToken));
		/*System.out.println(addActivateRoles(accessToken,role));
		System.out.println("-- Exporting the role: " + role + " to the domain: " + domain+ " --");
		System.out.println(exportRole(accessToken, role,domain));		
		PrivateKey privateKey = RSA.loadPrivateKey("utfpr_private.key");
		System.out.println("-- Requesting exported roles of domain: " + domain + " --");
		String cipherRoles = getExportedRoles(accessToken, domain);
		System.out.println(cipherRoles);
		System.out.println("-- Decrypt the exported roles with " + domain + " privateKey --");
		String decipherROles = RSA.decrypt(cipherRoles, privateKey);
		System.out.println(decipherROles);*/
			
		
		//TESTAR EXPORTAÇÃO DE PAPEL
		/*System.out.println(validarToken(token));
		System.out.println(getTrustedDomains(token));
		System.out.println(getRoles(token));
		System.out.println(addActivateRoles(token,role));
		System.out.println(exportRole(token, role,domain));		
		System.out.println(getActivateRoles(token));
		String resource = "button";
		String action = "read";
		System.out.println(requestAccess(token, resource, action));		
		System.out.println(dropActivateRoles(token,role));
		System.out.println(getActivateRoles(token));*/
		
		//TESTAR CONTROLE DE ACESSO
		/*String resource = "button";
		String action = "read";
		System.out.println(validarToken(token));
		System.out.println(getRoles(token));
		System.out.println(addActivateRoles(token,role));
		System.out.println(requestAccess(token, resource, action));
		System.out.println(dropActivateRoles(token,role));
		System.out.println(getActivateRoles(token));*/
		
		// TESTAR ATIVAÇÃO E SOD
		/*
		String roleConstraints = "admin";
		System.out.println(validarToken(token));
		System.out.println(getRoles(token));
		System.out.println(addConstraints(token, role, roleConstraints));
		System.out.println(getConstraints(token));
		System.out.println(addActivateRoles(token,role));
		System.out.println(addActivateRoles(token,roleConstraints));
		System.out.println(getActivateRoles(token));
		System.out.println(dropConstraints(token, role, roleConstraints));
		System.out.println(addActivateRoles(token,roleConstraints));		
		System.out.println(getActivateRoles(token));
		System.out.println(dropActivateRoles(token,role));
		System.out.println(dropActivateRoles(token,roleConstraints));
		System.out.println(getActivateRoles(token));
		*/
	}
}
