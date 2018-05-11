package process;

import org.json.JSONArray;
import org.json.JSONObject;
import client.GENERAL;
import controls.domains.Domain;
import controls.domains.DomainController;
import controls.rbac.User;
import crypto.Base_64;
import crypto.RSA;
import util.AuthProperties;

public class remote_access extends Thread
{	
	public void run()
	{
		try {
			for(int i = 0; i < 1000; i++)
				go();
		} 
		catch (java.lang.Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println(e.getMessage());
		}
	}
	public void go() throws java.lang.Exception
	{
		AuthProperties prop;
		DomainController domains = DomainController.getInstance();
		String domainName = RandomProcess.getRandomDomain();
		Domain d = domains.getDomain(domainName);
		prop = AuthProperties.init(d);		
				
		String randomUser = RandomProcess.getRandomUser() + "@" + domainName + ".com";
		LOGGING.print("User:" + randomUser);
		String authenticationCode = GENERAL.AuthenticateDefault(prop,randomUser);
		String code = GENERAL.getCode(prop,authenticationCode);
		String tokens = GENERAL.getTokens(prop, code);
		JSONObject jTokens = new JSONObject(tokens);	
		GENERAL.ImprimeTokens(tokens);
		String accessToken = jTokens.getString("access_token");
		String idToken = jTokens.getString("id_token");
						
		//TESTAR A PESQUISA DE PAPÉIS
		LOGGING.print("Userinfo: \t" + GENERAL.getUserInfo(prop,accessToken));
		String content = GENERAL.getRoles(prop,accessToken);		
		LOGGING.print("Avaliable roles: " + content);
		String activeRole;
		JSONObject jObject = new JSONObject(content);
		JSONArray listRoles = jObject.getJSONArray("roles");
		if( listRoles.length() <= 0 )
		{
			LOGGING.print(content);
			content = GENERAL.getActivateRoles(prop,accessToken);
			jObject = new JSONObject(content);
			listRoles = jObject.getJSONArray("roles");
			int randomRole = RandomProcess.nextInt(listRoles.length());
			JSONObject jCurrent = (JSONObject)listRoles.get(randomRole);
			jCurrent = (JSONObject)jCurrent.get("role");
			activeRole = jCurrent.getString("id");
		}
		else
		{
			int randomRole = RandomProcess.nextInt(listRoles.length());
			JSONObject jCurrent = (JSONObject)listRoles.get(randomRole);
			jCurrent = (JSONObject)jCurrent.get("role");
			activeRole = jCurrent.getString("id");
			LOGGING.print(GENERAL.addActivateRoles(prop,accessToken,activeRole));
		}
		LOGGING.print("Selected role:" + activeRole);
		
		
		
		
		String roles = GENERAL.getActivateRoles(prop,accessToken);
		LOGGING.print(roles);	
		AuthProperties propRemote;
		String externalDomain = RandomProcess.getOtherRandomDomain(domainName);
		d = domains.getDomain(externalDomain);
		propRemote = AuthProperties.init(d);
		
		String scopeRemote = GENERAL.buildRemoteScope(propRemote, randomUser, roles);
		code = GENERAL.getCode(propRemote, authenticationCode, scopeRemote);
		tokens = GENERAL.getTokens(propRemote, code, scopeRemote);	
		GENERAL.ImprimeTokens(tokens);
		jTokens = new JSONObject(tokens);	
		String remoteAccessToken = jTokens.getString("access_token");
				
		String cipherRoles = GENERAL.getExportedRoles(propRemote,remoteAccessToken, "furnas");
		User u = new User(randomUser);
		
		String exportedRoles = RSA.decrypt(cipherRoles, u.getPrivateKey());
		LOGGING.print(exportedRoles);
		
		jObject = new JSONObject(exportedRoles);
		JSONArray listExportedRoles = jObject.getJSONArray("exportedroles");
		String exportedRole = "";
		for( int i = 0; i < listExportedRoles.length(); i++ )
		{
			JSONObject jCurrent = (JSONObject)listExportedRoles.get(i);
			jCurrent = (JSONObject)jCurrent.get("role");
			String id = jCurrent.getString("id");
			exportedRole = id;
		}
		String signedRole = RSA.encrypt(exportedRole, u.getPrivateKey());
		signedRole = Base_64.encode(signedRole.getBytes());
		LOGGING.print(GENERAL.RemoteRoleActivation(propRemote, remoteAccessToken, exportedRole, signedRole));
		LOGGING.print(GENERAL.getActivateRoles(propRemote,remoteAccessToken));

		String resource = RandomProcess.getRandomResource();
		String action = RandomProcess.getRandomAction();
		LOGGING.printAlways("Acesso remoto:" + GENERAL.requestAccess(propRemote,remoteAccessToken, resource, action));

		LOGGING.print(GENERAL.dropActivateRoles(propRemote,remoteAccessToken,exportedRole));
		LOGGING.print(GENERAL.dropActivateRoles(prop,accessToken,activeRole));
	}
}
