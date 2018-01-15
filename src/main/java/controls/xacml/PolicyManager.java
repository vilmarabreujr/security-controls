package controls.xacml;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;

import org.wso2.carbon.identity.entitlement.common.EntitlementConstants;
import org.wso2.carbon.identity.entitlement.stub.dto.AttributeDTO;
import org.wso2.carbon.identity.entitlement.stub.dto.PaginatedPolicySetDTO;
import org.wso2.carbon.identity.entitlement.stub.EntitlementPolicyAdminServiceStub;
import org.wso2.carbon.identity.entitlement.stub.dto.PaginatedStatusHolder;
import org.wso2.carbon.identity.entitlement.stub.dto.PolicyDTO;
import org.wso2.carbon.identity.entitlement.stub.dto.StatusHolder;

import util.XACMLProperties;

public class PolicyManager 
{
	private String authCookie;
	private EntitlementPolicyAdminServiceStub policyAdminStub;
	private XACMLProperties properties;
	private String roleAttribute = "rbac_active_role";
	private String actionAttribute = "urn:oasis:names:tc:xacml:1.0:action:action-id";
	private String resourceAttribute = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
	
	
	public PolicyManager() throws Exception
	{
		policyAdminStub = null;
		authCookie = null;
		properties = XACMLProperties.inst();
		policyAdminStub = getStub();
	}
	
	public EntitlementPolicyAdminServiceStub getStub() throws AxisFault
	{
		if( policyAdminStub == null )
		{
			ConfigurationContext configContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);
            String serviceEndPoint = properties.getServerUrl() + "EntitlementPolicyAdminService";
            policyAdminStub = new EntitlementPolicyAdminServiceStub(configContext, serviceEndPoint);
            ServiceClient client = policyAdminStub._getServiceClient();

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
		}
		return policyAdminStub;
	}
	
	
	public String CreatePolicy(String role, String resource, String action)
	{
        try {            
        	Random r = new Random();
        	int id = r.nextInt();
            String samplePolicyName = "DynamicPolicy" + Integer.toString(id);
            String policy =  getTemplatePolicy(samplePolicyName, role, resource, action);

            PolicyDTO policyDTO = new PolicyDTO();
            policyDTO.setPolicy(policy);
            try{
                policyAdminStub.addPolicy(policyDTO);
            } catch (Exception e){
                e.printStackTrace();
            }

            policyAdminStub.publishToPDP(new String[]{samplePolicyName}, EntitlementConstants.PolicyPublish.ACTION_CREATE, null, false, 0);

            Thread.sleep(2000);
            PaginatedStatusHolder paginatedStatusHolder = policyAdminStub.
                    getStatusData(EntitlementConstants.Status.ABOUT_POLICY, samplePolicyName, EntitlementConstants.StatusTypes.PUBLISH_POLICY, "*", 1);
            StatusHolder statusHolder = paginatedStatusHolder.getStatusHolders()[0];
            if(statusHolder.getSuccess() && EntitlementConstants.PolicyPublish.ACTION_CREATE.equals(statusHolder.getTargetAction())){
                System.out.println("INFO : Policy is published successfully");
                return samplePolicyName;
            } else {
                System.out.println("INFO : Policy is failed to publish");
                return null;
            }            
        } 
        catch (Exception e) 
        {
            System.out.println("\nError :  " + e.getMessage());
            e.printStackTrace();
            authCookie = null;
            return null;
        }
	}
	
	public boolean DeletePolicy(String policyID)
	{
        try {            
            try{
                policyAdminStub.dePromotePolicy(policyID);
                Thread.sleep(2000);
                PaginatedStatusHolder paginatedStatusHolder = policyAdminStub.
                        getStatusData(EntitlementConstants.Status.ABOUT_POLICY, policyID, EntitlementConstants.StatusTypes.PUBLISH_POLICY, "*", 1);
                StatusHolder statusHolder = paginatedStatusHolder.getStatusHolders()[0];
                if(statusHolder.getSuccess() && EntitlementConstants.PolicyPublish.ACTION_DELETE.equals(statusHolder.getTargetAction())){
                    policyAdminStub.removePolicy(policyID, false);
                    System.out.println("INFO: Policy is deleted successfully");
                    return true;
                } else {
                    System.out.println("Error:  Policy is failed to delete");
                    return false;
                }
            } catch (Exception e){
                e.printStackTrace();
                return false;
            }
            
        } 
        catch (Exception e) 
        {
            System.out.println("Error :  " + e.getMessage());
            e.printStackTrace();
            authCookie = null;
            return false;
        }
	}
	
	public String getPolicy(String policyID)
	{
        try {          
            PolicyDTO policyDTO = policyAdminStub.getPolicy(policyID, false);      
            if( policyDTO == null )
            {
            	return null;
            }
            return policyDTO.getPolicy();
        } 
        catch (Exception e) 
        {
            System.out.println("\nError :  " + e.getMessage());
            e.printStackTrace();
            authCookie = null;
            return null;
        }
	}
	
	public String clonePolicyRole(String roleID)
	{
		PolicyDTO policyDTO = getPolicyByRole(roleID);
		if( policyDTO == null )
			return "Error: Policy doesn't exists";
				
		Map<String, ArrayList<String>> permissions = new HashMap<String, ArrayList<String>>();
		
		String resource = null;
		for( AttributeDTO attribute : policyDTO.getAttributeDTOs())
        {
			if( attribute.getAttributeId().equals(resourceAttribute) )
			{
				resource = attribute.getAttributeValue();
				ArrayList<String> resourcePermissions = permissions.get(resource);
				if( resourcePermissions == null )
				{
					resourcePermissions = new ArrayList<String>();
					permissions.put(resource, resourcePermissions);
				}
			}
			else if( attribute.getAttributeId().equals(actionAttribute) )
			{
				String action = attribute.getAttributeValue();
				ArrayList<String> resourcePermissions = permissions.get(resource);
				if( resourcePermissions == null )
				{
					resourcePermissions = new ArrayList<String>();
				}
				resourcePermissions.add(action);
				permissions.put(resource, resourcePermissions);				
			}
        }
		

    	Random r = new Random();
    	int id = r.nextInt();
        String newPolicyID = "DynamicPolicy" + Integer.toString(id);
		String policyString = getTemplatePolicy(newPolicyID, "doutorando", permissions);				
		return policyString;
	}
	
	public PolicyDTO getPolicyByRole(String roleID)
	{
        try {          
        	String[] policies = policyAdminStub.getAllPolicyIds("");
        	for( String policyID : policies )
        	{
                PolicyDTO policyDTO = policyAdminStub.getPolicy(policyID, false);
                if( policyDTO != null )
                {
                	for( AttributeDTO attribute : policyDTO.getAttributeDTOs())
                    {
                    	if( attribute.getAttributeId().equals(roleAttribute) )
                    	{
                    		if( attribute.getAttributeValue().equals(roleID) )
                        	{
                    			return policyDTO;
                        	}
                    		else
                    			break;
                    	}
                    }
                }
        	}
            
            return null;
        } 
        catch (Exception e) 
        {
            System.out.println("\nError :  " + e.getMessage());
            e.printStackTrace();
            authCookie = null;
            return null;
        }
	}
	
	private  String getTemplatePolicy(String policyID, String role, Map<String, ArrayList<String>> permissions){
		String policy = 
					"<Policy xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\"  PolicyId=\"" + policyID + "\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable\" Version=\"1.0\">"+
					"   <Target></Target>";
		int ruleCount = 0;
		for( String resource : permissions.keySet() )
		{
			ArrayList<String> resourcePermissions = permissions.get(resource);
			for( String action : resourcePermissions )
			{
				policy +=		
						"   <Rule Effect=\"Permit\" RuleId=\"rule_" + Integer.toString(ruleCount) +"\">" +
						"      <Target>" +
						"         <AnyOf>" +
						"            <AllOf>" +
						"               <Match MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\">"+
						"                  <AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + resource + "</AttributeValue>"+
						"                  <AttributeDesignator AttributeId=\"urn:oasis:names:tc:xacml:1.0:resource:resource-id\" Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:resource\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"true\"></AttributeDesignator>"+
						"               </Match>" +
						"            </AllOf>"+
						"         </AnyOf>"+
						"         <AnyOf>"+
						"            <AllOf>"+
						"               <Match MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\">"+
						"                  <AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + action + "</AttributeValue>"+
						"                  <AttributeDesignator AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\" Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:action\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"true\"></AttributeDesignator>"+
						"               </Match>"+
						"            </AllOf>"+
						"         </AnyOf>"+
						"      </Target>"+
						"      <Condition>"+
						"         <Apply FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:any-of\">"+
						"            <Function FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\"></Function>"+
						"            <AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + role + "</AttributeValue>"+
						"            <AttributeDesignator AttributeId=\"rbac_active_role\" Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"true\"></AttributeDesignator>"+
						"         </Apply>"+
						"     </Condition>"+
						"   </Rule>";	
				ruleCount++;
			}
		}		
		
		policy += 	"   <Rule Effect=\"Deny\" RuleId=\"denyall\"></Rule>"+
					"</Policy>"     ;   
		return policy;
    }
	
	private  String getTemplatePolicy(String policyID, String role, String resource, String action){

        return "<Policy xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" PolicyId=\"" + policyID + "\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable\" Version=\"1.0\">\n" +
                "   <Target>\n" +
                "      <AnyOf>\n" +
                "         <AllOf>\n" +
                "            <Match MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\">\n" +
                "               <AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + resource + "</AttributeValue>\n" +
                "               <AttributeDesignator AttributeId=\"urn:oasis:names:tc:xacml:1.0:resource:resource-id\" Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:resource\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"true\"/>\n" +
                "            </Match>\n" +
                "         </AllOf>\n" +
                "      </AnyOf>\n" +
                "   </Target>\n" +
                "   <Rule Effect=\"Permit\" RuleId=\"Rule-1\">\n" +
                "      <Target>\n" +
                "         <AnyOf>\n" +
                "            <AllOf>\n" +
                "               <Match MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\">\n" +
                "                  <AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + action + "</AttributeValue>\n" +
                "                  <AttributeDesignator AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\" Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:action\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"true\"/>\n" +
                "               </Match>\n" +
                "            </AllOf>\n" +
                "         </AnyOf>\n" +
                "      </Target>\n" +
                "      <Condition>\n" +
                "         <Apply FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:any-of\">\n" +
                "            <Function FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\"/>\n" +
                "            <AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">" + role + "</AttributeValue>\n" +
                "            <AttributeDesignator AttributeId=\"rbac_active_role\" Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"true\"/>\n" +
                "         </Apply>\n" +
                "      </Condition>\n" +
                "   </Rule>\n" +
                "   <Rule Effect=\"Deny\" RuleId=\"Deny-Rule\"/>\n" +
                "</Policy> ";
    }
}
