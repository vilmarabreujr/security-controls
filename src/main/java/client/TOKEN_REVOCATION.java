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

public class TOKEN_REVOCATION 
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
	
	public static String revogar(String token) throws Exception
	{
		String clientID = prop.getConsumerKey();
		String clientPWD = prop.getConsumerSecret();
		URL obj = new URL("https://localhost:9443/oauth2endpoints/revoke");
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional default is GET
		con.setRequestMethod("POST");

		//add request header
		//con.setRequestProperty("User-Agent", "Mozilla/5.0");
		String encoded = Base64.getEncoder().encodeToString((clientID+":"+clientPWD).getBytes(StandardCharsets.UTF_8));
		con.setRequestProperty("Authorization", "Basic " + encoded);
		con.setRequestProperty("Content-Type","application/x-www-form-urlencoded;charset=UTF-8"); 
		con.setDoOutput(true);
		
		String str =  "token=" + token + "&token_type_hint=access_token&callback=" + prop.getCallBackURL();
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
		System.out.println(jsonString);
		//JSONObject jObject = new JSONObject(jsonString);		
		//print result
		return jsonString;
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

		System.out.println("Userinfo: \t" + GENERAL.getUserInfo(prop,accessToken));
		System.out.println(revogar(accessToken));
		System.out.println("Userinfo: \t" + GENERAL.getUserInfo(prop,accessToken));
	}
}
