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
import util.AuthProperties;
import util.HttpConnection;
import util.JWT;

public class GENERAL {
	public static String Authenticate(AuthProperties p, String user, String password) throws Exception
	{		
		String clientID = p.getConsumerKey();
		String clientPWD = p.getConsumerSecret();
		URL obj = new URL(p.getTokenEndpoint());
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
	
	public static String getCode(AuthProperties p, String authenticationCode) throws Exception
	{	
		return getCode(p,authenticationCode, p.getScope());
	}
	
	public static String getCode(AuthProperties p, String authenticationCode, String scope) throws Exception
	{
		String clientID = p.getConsumerKey();
		String callBackURL = p.getCallBackURL();
		URL obj = new URL(p.getAuthzEndpoint());
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional default is GET
		con.setRequestMethod("POST");

		//add request header
		con.setRequestProperty("Authorization", "Bearer " + authenticationCode);
		con.setRequestProperty("Content-Type","application/x-www-form-urlencoded;charset=UTF-8"); 
		con.setDoOutput(true);
		con.setInstanceFollowRedirects(false);
		
		String str =  "response_type=code&client_id=" + clientID + "&redirect_uri=" + callBackURL + "&scope=" + scope;
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
	public static String getTokens(AuthProperties p, String code) throws Exception
	{
		return getTokens(p,code,p.getScope());
	}
	
	public static String getTokens(AuthProperties p, String code, String scope) throws Exception
	{
		String clientID = p.getConsumerKey();
		String clientPWD = p.getConsumerSecret();
		String callBackURL = p.getCallBackURL();
		URL obj = new URL(p.getTokenEndpoint());
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional default is GET
		con.setRequestMethod("POST");

		//add request header
		//con.setRequestProperty("User-Agent", "Mozilla/5.0");
		String encoded = Base64.getEncoder().encodeToString((clientID+":"+clientPWD).getBytes(StandardCharsets.UTF_8));  //Java 8
		con.setRequestProperty("Authorization", "Basic "+encoded);
		con.setRequestProperty("Content-Type","application/x-www-form-urlencoded;charset=UTF-8"); 
		con.setDoOutput(true);
		
		String str =  "grant_type=authorization_code&client_id=" + clientID + "&redirect_uri=" + callBackURL + "&code=" + code + "&scope=" + scope;
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
		System.out.println(response);
		//print result
		return response.toString();
	}
	
	public static void ImprimeTokens(String tokens) throws Exception
	{
		JSONObject jTokens = new JSONObject(tokens);	
		String accessToken = jTokens.getString("access_token");
		String idToken = jTokens.getString("id_token");		
		System.out.println("acessToken: " + accessToken);
		System.out.println("idToken: " + idToken);
		JWT.processToken(idToken);
	}
	
	public static String validarToken(AuthProperties p, String token) throws Exception
	{
		String url = p.getSecurityControlsURL() + "validate-token?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String getRoles(AuthProperties prop,String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String getUserInfo(AuthProperties prop,String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "user-information?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String getActivateRoles(AuthProperties prop,String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/activated?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String addActivateRoles(AuthProperties prop,String token, String roleID) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/activated?accessToken=" + token + "&role=" + roleID;
		String response = HttpConnection.sendPost(url);
		return response;
	}
	
	public static String dropActivateRoles(AuthProperties prop,String token, String roleID) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/activated?accessToken=" + token + "&role=" + roleID;
		String response = HttpConnection.sendDelete(url);
		return response;
	}
	
	public static String getConstraints(AuthProperties prop,String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/constraints?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String addConstraints(AuthProperties prop,String token, String roleA, String roleB) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/constraints?accessToken=" + token + "&roleA=" + roleA + "&roleB=" + roleB;
		String response = HttpConnection.sendPost(url);
		return response;
	}
	
	public static String dropConstraints(AuthProperties prop,String token, String roleA, String roleB) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "rbac/constraints?accessToken=" + token + "&roleA=" + roleA + "&roleB=" + roleB;
		String response = HttpConnection.sendDelete(url);
		return response;
	}
	
	public static String requestAccess(AuthProperties prop,String token, String resource, String action) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "access-control?accessToken=" + token + "&resource=" + resource + "&action=" + action;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String exportRole(AuthProperties prop,String token, String role, String domain, String registerdRole) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "wallet?accessToken=" + token + "&role=" + role+ "&domain=" + domain+ "&registerdRole=" + registerdRole;
		String response = HttpConnection.sendPost(url);
		return response;
	}	
	
	public static String getExportedRoles(AuthProperties prop,String token, String domain) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "wallet?accessToken=" + token + "&domain=" + domain;
		String response = HttpConnection.sendGet(url);
		return response;
	}

	public static String getTrustedDomains(AuthProperties prop,String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "domain?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}
	
	public static String getRegisteredRoles(AuthProperties prop,String token) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "wallet/registered?accessToken=" + token;
		String response = HttpConnection.sendGet(url);
		return response;
	}	
	
	public static String setRegisteredRoles(AuthProperties prop,String token, String role) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "wallet/registered?accessToken=" + token + "&role=" + role;
		String response = HttpConnection.sendPost(url);
		return response;
	}
	
	public static String RemoteRoleActivation(AuthProperties prop,String token, String exportedRole, String signedRole) throws Exception
	{
		String url = prop.getSecurityControlsURL() + "wallet?accessToken=" + token + "&exportedRole=" + exportedRole + "&signedRole=" + signedRole;
		String response = HttpConnection.sendPut(url);
		return response;
	}
}
