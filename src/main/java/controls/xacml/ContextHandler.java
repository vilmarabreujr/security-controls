package controls.xacml;


import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.XML;
import org.wso2.carbon.identity.entitlement.stub.EntitlementServiceStub;

import util.XACMLProperties;


public class ContextHandler 
{
	private String authCookie = null;
	private XACMLProperties properties;
	public ContextHandler() throws Exception
	{
		properties = XACMLProperties.inst();
	}
	
	public boolean ValidateResponse(String xmlString)
	{				
		try {
			JSONObject jsonReturn = XML.toJSONObject(xmlString);
			JSONObject jsonResponse = jsonReturn.getJSONObject("Response");
			JSONObject jsonResult = jsonResponse.getJSONObject("Result");
			String decision = jsonResult.get("Decision").toString();
			if( decision.equals("Permit") )
				return true;
			else if( decision.equals("Deny") )
				return false;
			if( decision.equals("NotApplicable") )
				return false;
			return false;
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		
	}
	
	public boolean ValidateRequest(String token, String resource, String action)
	{
		ConfigurationContext configContext;

        try {

            /**
             * Create a configuration context. A configuration context contains information for
             * axis2 environment. This is needed to create an axis2 client
             */
            configContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);
            String serviceEndPoint = properties.getServerUrl() + "EntitlementService";
            EntitlementServiceStub entitlementServiceStub = new EntitlementServiceStub(configContext, serviceEndPoint);
            ServiceClient client = entitlementServiceStub._getServiceClient();

            Options option = client.getOptions();
            option.setManageSession(true);
            option.setProperty(HTTPConstants.COOKIE_STRING, authCookie);            
            
            if( authCookie == null )
            {
                /**
                 * Setting basic auth headers for authentication for user admin
                 */
            	HttpTransportProperties.Authenticator auth = new HttpTransportProperties.Authenticator();
                auth.setUsername(properties.getServerUsername());
                auth.setPassword(properties.getServerPassword());
                auth.setPreemptiveAuthentication(true);
                option.setProperty(org.apache.axis2.transport.http.HTTPConstants.AUTHENTICATE, auth);
            }
            String decision = entitlementServiceStub.getDecisionByAttributes(token, resource, action, null);
            System.out.println(XML.toJSONObject(decision).toString());
            authCookie = (String) entitlementServiceStub._getServiceClient().getServiceContext().getProperty(HTTPConstants.COOKIE_STRING);     
            return ValidateResponse(decision);
        } 
        catch (Exception e) 
        {
            System.out.println("\nError :  " + e.getMessage());
            e.printStackTrace();
            authCookie = null;
            return false;
        }
	}
}
