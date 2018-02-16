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

public class FURNAS_ADMIN 
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
		String domainName = "furnas";
		DomainController domains = DomainController.getInstance();
		Domain d = domains.getDomain(domainName);
		prop = AuthProperties.init(d);
	}
	
	public static AuthProperties prop;
	
	
	
		
		
	public static String validarToken(String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "validate-token?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
		
	public static String getUserInfo(String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "user-information?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}	
	
	public static String getRegisteredRoles(String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "wallet/registered?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String setRegisteredRoles(String token, String role) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "wallet/registered?accessToken=" + token + "&role=" + role;
		String response = HttpConnection.sendPost(url);
		return response;
	}
	
	public static String getRoles(String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static void main(String[] args) throws Exception 
	{
		init();
		String authenticationCode = GENERAL.Authenticate(prop,"admin@furnas.com", "admin");
		String code = GENERAL.getCode(prop, authenticationCode);
		String tokens = GENERAL.getTokens(prop, code);
		JSONObject jTokens = new JSONObject(tokens);	
		String accessToken = jTokens.getString("access_token");
		String idToken = jTokens.getString("id_token");
		
		System.out.println("acessToken: " + accessToken);
		System.out.println("idToken: " + idToken);

		System.out.println(setRegisteredRoles(accessToken, "operator"));
		System.out.println(getRegisteredRoles(accessToken));
	}
}
