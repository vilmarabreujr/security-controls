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
    private final String EXTERNAL_ROLE_ID = "rbac_sra_role";
    private final String EXPORTED_ROLE_ID = "rbac_exported_role";
    private String ExternalDomain = "";
    private Map<String, Set<String> > EstruturaBD;
    private boolean cacheEnable = false;

    @Override
	public void init(Properties properties)  throws Exception{
        supportedAttributes.add(ACTIVE_ROLE_ID);
        //supportedAttributes.add(EXTERNAL_ROLE_ID);
        EstruturaBD = new HashMap<String, Set<String>>();
    }

    @Override
    public String getModuleName() {
        return "RBAC";
    }
        
    @Override
    public Set<String> getAttributeValues(String subjectId, String resourceId, String actionId,
                                          String environmentId, String attributeId, String issuer) throws Exception{

		
    	if(!ACTIVE_ROLE_ID.equals(attributeId) && !EXTERNAL_ROLE_ID.equals(attributeId) ){
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
	    		
	    		/*if(EXTERNAL_ROLE_ID.equals(attributeId))
	    		{  			
					content = getExternalRoles(subjectId);  
	        		jObject = new JSONObject(content);
	        		listAppliances = jObject.getJSONArray("roles");
	        		            		
	        		for( int i = 0; i < listAppliances.length(); i++ )
	        		{
	        			JSONObject jCurrent = (JSONObject)listAppliances.get(i);
	        			jCurrent = (JSONObject)jCurrent.get("role");
	        			String id = ExternalDomain + "." + jCurrent.getString("id");
	        			values.add(id);
	        		}      		
	            } 	    		

	    		if(EXPORTED_ROLE_ID.equals(attributeId))
	    		{  			
					content = getExportedRole(subjectId);  
	        		jObject = new JSONObject(content);
	        		listAppliances = jObject.getJSONArray("roles");
	        		            		
	        		for( int i = 0; i < listAppliances.length(); i++ )
	        		{
	        			JSONObject jCurrent = (JSONObject)listAppliances.get(i);
	        			jCurrent = (JSONObject)jCurrent.get("role");
	        			String id = jCurrent.getString("id");
	        			values.add(id);
	        		}      		
	            }*/
	    		
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
		return supportedAttributes;
	}
    
    public String getActivateRoles(String acessToken)
	{
		String returnValue = null;
		try 
		{					
			String url = "https://localhost:8443/securitycontrols/api/rbac/activated?accessToken=" + acessToken;
			returnValue = sendGet(url);
		} 
		catch (Exception e) 
		{
			// TODO Auto-generated catch block
    		System.out.println(e.getMessage());
			e.printStackTrace();
			
		}		
		return returnValue;
	}    
    
    /*public String getExternalRoles(String accessToken)
	{
		String returnValue = null;
		try 
		{		
			String urlRBAC = getURLRBAC(accessToken);
			String rbacURL = urlRBAC + "controller";
			rbacURL += "?";
			rbacURL += "token=" + accessToken;
			rbacURL += "&";
			rbacURL += "type=1";
			
			HTTPRequest httpRequest = new HTTPRequest(Method.GET, new URL(rbacURL));
			HTTPResponse httpResponse = httpRequest.send();

			returnValue = httpResponse.getContent();
		} 
		catch (Exception e) 
		{
			// TODO Auto-generated catch block
    		System.out.println(e.getMessage());
			e.printStackTrace();
			
		}		
		return returnValue;
	}
    
    public String getExportedRole(String accessToken)
	{
		String returnValue = null;
		try 
		{		
			String urlRBAC = getURLRBAC(accessToken);
			String rbacURL = urlRBAC + "wallet";
			rbacURL += "?";
			rbacURL += "token=" + accessToken;
			rbacURL += "&";
			rbacURL += "type=1";
			
			HTTPRequest httpRequest = new HTTPRequest(Method.GET, new URL(rbacURL));
			HTTPResponse httpResponse = httpRequest.send();

			returnValue = httpResponse.getContent();
		} 
		catch (Exception e) 
		{
			// TODO Auto-generated catch block
    		System.out.println(e.getMessage());
			e.printStackTrace();
			
		}		
		return returnValue;
	}
    
    public String getURLRBAC(String accessToken)
	{
		String returnValue = null;
		try 
		{					
			UserInfoRequest userInfoReq = new UserInfoRequest(new URI("https://domain-c:8443/c2id/userinfo"), new BearerAccessToken(accessToken));		
			HTTPRequest httpRequest = userInfoReq.toHTTPRequest();
			HTTPResponse httpResponse = httpRequest.send();
			UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

			if (userInfoResponse instanceof UserInfoErrorResponse) 
			{
				UserInfoErrorResponse userInfoErrorResponse = (UserInfoErrorResponse)userInfoResponse;

				String msg = "[ " + userInfoErrorResponse.getErrorObject().getCode() + " ] ";
				msg += userInfoErrorResponse.getErrorObject().getDescription();		
				ExternalDomain = "";
	    		System.out.println("Error: " + msg);
			}
			else
			{
				UserInfoSuccessResponse userInfoSuccessResponse = (UserInfoSuccessResponse)userInfoResponse;
				UserInfo user = userInfoSuccessResponse.getUserInfo();	
				String home = user.getStringClaim("home");
				String rbac_home = user.getStringClaim("rbac_home");

				ExternalDomain = home;
				returnValue = rbac_home;
			}	
		} 
		catch (Exception e) 
		{
			// TODO Auto-generated catch block
    		System.out.println(e.getMessage());
			e.printStackTrace();
			
		}		
		return returnValue;
	} */
    
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
