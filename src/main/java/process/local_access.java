package process;

import org.json.JSONArray;
import org.json.JSONObject;

import client.GENERAL;
import controls.domains.Domain;
import controls.domains.DomainController;
import util.AuthProperties;
import util.HttpConnection;
import util.XACMLProperties;

public class local_access 
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
		
		
	}
	public static AuthProperties prop;
	public static AuthProperties propRemote;	
	
	
	public static void main(String[] args) throws Exception 
	{
		DomainController domains = DomainController.getInstance();
		String domainName = RandomProcess.getRandomDomain();
		//Temp
		domainName = "eletrobras";
		Domain d = domains.getDomain(domainName);
		prop = AuthProperties.init(d);		
				
		String randomUser = RandomProcess.getRandomUser() + "@" + domainName + ".com";
		System.out.println(randomUser);
		String authenticationCode = GENERAL.AuthenticateDefault(prop,randomUser);
		String code = GENERAL.getCode(prop,authenticationCode);
		String tokens = GENERAL.getTokens(prop, code);
		JSONObject jTokens = new JSONObject(tokens);	
		GENERAL.ImprimeTokens(tokens);
		String accessToken = jTokens.getString("access_token");
		String idToken = jTokens.getString("id_token");
						
		//TESTAR A PESQUISA DE PAPÉIS
		System.out.println("Userinfo: \t" + GENERAL.getUserInfo(prop,accessToken));
		String content = GENERAL.getRoles(prop,accessToken);		
		System.out.println("Avaliable roles: " + content);
		
		JSONObject jObject = new JSONObject(content);
		JSONArray listRoles = jObject.getJSONArray("roles");
		int randomRole = RandomProcess.nextInt(listRoles.length());
		JSONObject jCurrent = (JSONObject)listRoles.get(randomRole);
		jCurrent = (JSONObject)jCurrent.get("role");
		String activeRole = jCurrent.getString("id");
		System.out.println(activeRole);
		
		System.out.println(GENERAL.addActivateRoles(prop,accessToken,activeRole));
		System.out.println(GENERAL.getActivateRoles(prop,accessToken));	
		String resource = "button";
		String action = "read";
		System.out.println(GENERAL.requestAccess(prop,accessToken, resource, action));
		System.out.println(GENERAL.dropActivateRoles(prop,accessToken,activeRole));
		/*
		//Processo de acesso a recurso local protegido
		String activeRole = "enginner";
		System.out.println(GENERAL.addActivateRoles(prop,accessToken,activeRole));
		System.out.println(GENERAL.getTrustedDomains(prop,accessToken));
		System.out.println(GENERAL.getActivateRoles(prop,accessToken));	
		System.out.println(GENERAL.requestAccess(prop,accessToken, "button", "read"));
		
		//Processo de exportação
		String externalDomain = "furnas";
		System.out.println(GENERAL.getRegisteredRoles(propRemote,accessToken));
		String registeredRole = "operator";		
		System.out.println(GENERAL.exportRole(prop,accessToken, activeRole,externalDomain, registeredRole));*/
		
		//System.out.println(GENERAL.dropActivateRoles(prop,accessToken,activeRole));		
		
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
