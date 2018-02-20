package controls.xacml;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.entitlement.pip.AbstractPIPAttributeFinder;

// jar /home/aluno/Documentos/wso2is-5.3.0/repository/components/lib/AttributeFinderRBAC.jar
public class AttributeFinderRBAC extends AbstractPIPAttributeFinder {
	
	static 
	{
	    //for localhost testing only
	    javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
	    new javax.net.ssl.HostnameVerifier(){
 
	        public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession) 
	        {
	            return true;
	        }
	    });
	}

	private Set<String> supportedAttributes = new HashSet<String>();
	    
    private final String ACTIVE_ROLE_ID = "rbac_active_role";
    private final String WALLET_ROLE_ID = "wallet_active_role";
    private Map<String, Set<String> > EstruturaBD;
    private boolean cacheEnable = false;

    @Override
	public void init(Properties properties)  throws Exception{
        supportedAttributes.add(ACTIVE_ROLE_ID);
        supportedAttributes.add(WALLET_ROLE_ID);
        EstruturaBD = new HashMap<String, Set<String>>();
    }

    @Override
    public String getModuleName() {
        return "RBAC";
    }
        
        
    @Override
    public Set<String> getAttributeValues(String subjectId, String resourceId, String actionId,
                                          String environmentId, String attributeId, String issuer) throws Exception{
    	System.out.println("PIP personalizado!");
    	if(!ACTIVE_ROLE_ID.equals(attributeId) && !WALLET_ROLE_ID.equals(attributeId) ){
            return null;
        }
		Set<String> values = new HashSet<String>();
    	try 
    	{
    		boolean buscarValores = true;
			if( cacheEnable )
			{
				Set<String> valuesCache = EstruturaBD.get(subjectId);
				if( valuesCache != null )
				{
					buscarValores = false;
					for (String s : valuesCache) 
					{
		    			values.add(s);
					}
				}
			}
			if( buscarValores )
			{
				String content = getActivateRoles(subjectId); 
	    		
	        	JSONObject jObject = new JSONObject(content);
	    		JSONArray listRoles = jObject.getJSONArray("activeroles");
	    		if( listRoles == null )
	    			return null;
	    		for( int i = 0; i < listRoles.length(); i++ )
	    		{
	    			JSONObject jCurrent = (JSONObject)listRoles.get(i);
	    			jCurrent = (JSONObject)jCurrent.get("role");
	    			String id = jCurrent.getString("id");
	    			values.add(id);
	    		}
	    		
	    		if( cacheEnable )
    			{
        			EstruturaBD.put(subjectId, values);
    			} 
			}
    	}
    	catch (Exception e) 
    	{
    		System.out.println(e.getMessage());
		}
    	
    	if( cacheEnable && EstruturaBD.size() > 10000 )
    	{
    		EstruturaBD = new HashMap<String, Set<String>>();
    		System.out.println("Resetou hash");
    	}
    	
		return values;
    	
	}
    
    @Override
	public Set<String> getSupportedAttributes() {
    	System.out.println("getSupportedAttributes");
		return supportedAttributes;
	}
    
    public String getActivateRoles(String acessToken)
	{
		String returnValue = null;
		try 
		{					
			String rbabUrl = getDomainURL(acessToken);
			String url = rbabUrl + "rbac/activated?accessToken=" + acessToken;
			System.out.println("url: " + url);
			returnValue = sendGet(url);
			System.out.println("retorno: " + returnValue);
		} 
		catch (Exception e) 
		{
			// TODO Auto-generated catch block
    		System.out.println(e.getMessage());
			e.printStackTrace();
			
		}		
		return returnValue;
	}    
        
    public static String validarToken(String accessToken)
	{
    	try
    	{
    		String securityControlUrl = "https://localhost:8443/securitycontrols/furnas/";
    		String url = securityControlUrl + "validate-token?accessToken=" + accessToken;
    		String response = sendGet(url);
    		return response;
    	}
    	catch (Exception e) {
			// TODO: handle exception
    		return null;
		}
		
	}
    
    public static String getDomainURL(String accessToken)
	{
    	try
    	{
    		String validation = validarToken(accessToken);
        	
    		JSONObject jTokens = new JSONObject(validation);	
    		if( !jTokens.has("scope") )
    			return null;

    		String[] scopes = jTokens.getString("scope").split(" ");
    		
    		for(String s : scopes )
    		{
    			if( s.equals("furnas") )
    			{
    				return "https://localhost:8443/securitycontrols/furnas/";
    			}
    			else if( s.equals("copel") )
    			{
    				return "https://localhost:8443/securitycontrols/copel/";
    			}
    		}
    		return null;
    	}
    	catch(Exception e)
    	{
    		System.out.println("Deu pau: " + e.getMessage());
    		e.printStackTrace();
    		return null;
    	}    	
	}
    
    public static String sendGet(String url) throws Exception {

		URL obj = new URL(url);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		// optional default is GET
		con.setRequestMethod("GET");

		//add request header
		con.setRequestProperty("User-Agent", "Mozilla/5.0");

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
}
