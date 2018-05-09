package process;

import org.json.JSONArray;
import org.json.JSONObject;

import client.GENERAL;
import controls.domains.Domain;
import controls.domains.DomainController;
import util.AuthProperties;

public class register_imported_roles  extends Thread
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
				
		String randomUser = "alice" + "@" + domainName + ".com";
		System.out.println("User:" + randomUser);
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
		
		String activeRole = "admin";
		System.out.println("Selected role: " + activeRole);
		
		System.out.println(GENERAL.addActivateRoles(prop,accessToken,activeRole));
		content = GENERAL.getDomainRoles(prop,accessToken);
		JSONObject jObject = new JSONObject(content);
		JSONArray listRoles = jObject.getJSONArray("domainroles");
		int randomRole = RandomProcess.nextInt(listRoles.length());
		JSONObject jCurrent = (JSONObject)listRoles.get(randomRole);
		jCurrent = (JSONObject)jCurrent.get("role");
		String importedRole = jCurrent.getString("id");		

		System.out.println(GENERAL.setRegisteredRoles(prop,accessToken, importedRole));
		System.out.println(GENERAL.getRegisteredRoles(prop,accessToken));
		System.out.println(GENERAL.dropActivateRoles(prop,accessToken,activeRole));
	}
}
