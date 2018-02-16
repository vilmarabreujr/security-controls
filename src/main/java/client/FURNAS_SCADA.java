package client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Base64;

import org.json.JSONObject;

import controls.domains.Domain;
import controls.domains.DomainController;
import controls.rbac.User;
import crypto.Base_64;
import crypto.RSA;
import util.AuthProperties;
import util.HttpConnection;
import util.JWT;

public class FURNAS_SCADA 
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
		DomainController domains = DomainController.getInstance();
		
		String domainName = "furnas";
		Domain d = domains.getDomain(domainName);
		prop = AuthProperties.init(d);
		
		domainName = "copel";
		d = domains.getDomain(domainName);
		propRemote = AuthProperties.init(d);
		
	}
	public static AuthProperties prop;
	public static AuthProperties propRemote;
	
	public static String buildRemoteScope(String user, String roles)
	{
		String complemento = "";

		try 
		{
			User u = new User(user);
			String kpu = RSA.publicKeyToString(u.getPublicKey());
				
			//String kpu = user + "_public.key";
			JSONObject jComplemento = new JSONObject(roles);
			jComplemento.append("kpu", kpu);
			complemento = jComplemento.toString();	
			complemento = Base_64.encode(complemento.getBytes());
		} 
		catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String scope = "openid " + complemento;		
		
		System.err.println(scope);
		
		return scope;
	}
	
	public static void main(String[] args) throws Exception 
	{
		init();
		String user = "bob@furnas.com";
		
		String authenticationCode = GENERAL.Authenticate(prop,user, "secret");
		String code = GENERAL.getCode(prop, authenticationCode);
		String tokens = GENERAL.getTokens(prop, code);
		
		JSONObject jTokens = new JSONObject(tokens);	
		GENERAL.ImprimeTokens(tokens);
		String accessToken = jTokens.getString("access_token");
						
		//TESTAR A PESQUISA DE PAPÉIS
		System.out.println("Userinfo: \t" + GENERAL.getUserInfo(prop,accessToken));
		System.out.println(GENERAL.getRoles(prop,accessToken));
		

		//Processo de acesso a recurso local protegido
		String activeRole = "operator";
		System.out.println(GENERAL.addActivateRoles(prop,accessToken,activeRole));
		System.out.println(GENERAL.getTrustedDomains(prop,accessToken));
		String roles = GENERAL.getActivateRoles(prop,accessToken);
		System.out.println(roles);	
		
		String scopeRemote = buildRemoteScope(user, roles);
		code = GENERAL.getCode(propRemote, authenticationCode, scopeRemote);
		tokens = GENERAL.getTokens(propRemote, code, scopeRemote);	
		GENERAL.ImprimeTokens(tokens);
		jTokens = new JSONObject(tokens);	
		String remoteAccessToken = jTokens.getString("access_token");
		System.out.println(GENERAL.validarToken(propRemote,remoteAccessToken));
		
				
		//String cipherRoles = getExportedRoles(accessToken, domain);
		
		System.out.println(GENERAL.dropActivateRoles(prop,accessToken,activeRole));
		
		
		/*
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
