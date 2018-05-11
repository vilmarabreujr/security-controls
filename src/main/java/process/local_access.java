package process;

import org.json.JSONArray;
import org.json.JSONObject;
import client.GENERAL;
import controls.domains.Domain;
import controls.domains.DomainController;
import util.AuthProperties;

public class local_access extends Thread
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
	
	public String getRandomRole(String content)
	{
		JSONObject jObject = new JSONObject(content);
		
		for( String key : jObject.keySet() )
		{
			JSONArray listRoles = jObject.getJSONArray(key);
			if( listRoles == null || listRoles.length() == 0 )
				return null;
			int randomRole = RandomProcess.nextInt(listRoles.length());
			JSONObject jCurrent = (JSONObject)listRoles.get(randomRole);
			jCurrent = (JSONObject)jCurrent.get("role");
			String selectedRole = jCurrent.getString("id");
			return selectedRole;
		}
		return null;
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
		LOGGING.print("roles: " + content);
		
		String activeRole = getRandomRole(content);
		if( activeRole == null )
		{
			content = GENERAL.getActivateRoles(prop,accessToken);
			activeRole = getRandomRole(content);
		}
		else
		{
			LOGGING.print(GENERAL.addActivateRoles(prop,accessToken,activeRole));	
		}
		LOGGING.print("Selected role:" + activeRole);
		LOGGING.print(GENERAL.getActivateRoles(prop,accessToken));	
		String resource = RandomProcess.getRandomResource();
		String action = RandomProcess.getRandomAction();
		LOGGING.printAlways("Acesso local:" + GENERAL.requestAccess(prop,accessToken, resource, action));
		LOGGING.print(GENERAL.dropActivateRoles(prop,accessToken,activeRole));
	}
}
