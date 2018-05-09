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
			for(int i = 0; i < 10; i++)
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
		
		JSONObject jObject = new JSONObject(content);
		JSONArray listRoles = jObject.getJSONArray("roles");
		int randomRole = RandomProcess.nextInt(listRoles.length());
		JSONObject jCurrent = (JSONObject)listRoles.get(randomRole);
		jCurrent = (JSONObject)jCurrent.get("role");
		String activeRole = jCurrent.getString("id");
		LOGGING.print("Selected role:" + activeRole);
		
		LOGGING.print(GENERAL.addActivateRoles(prop,accessToken,activeRole));
		LOGGING.print(GENERAL.getActivateRoles(prop,accessToken));	
		String resource = RandomProcess.getRandomResource();
		String action = RandomProcess.getRandomAction();
		LOGGING.print(GENERAL.requestAccess(prop,accessToken, resource, action));
		LOGGING.print(GENERAL.dropActivateRoles(prop,accessToken,activeRole));
	}
}
