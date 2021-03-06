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

import controls.domains.Domain;
import util.XACMLProperties;

public class PolicyManager 
{
	private String authCookie;
	private EntitlementPolicyAdminServiceStub policyAdminStub;
	private XACMLProperties properties;
	private String roleAttribute = "rbac_active_role";
	private String actionAttribute = "urn:oasis:names:tc:xacml:1.0:action:action-id";
	private String resourceAttribute = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
	
	
	public PolicyManager(Domain d) throws Exception
	{
		policyAdminStub = null;
		authCookie = null;
		properties = XACMLProperties.init(d);
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
	
	
	public String CreatePolicy(PolicyDTO policyDTO)
	{
        try {       
            policyAdminStub.addPolicy(policyDTO);
            String policyID = policyDTO.getPolicyId();
            policyAdminStub.publishToPDP(new String[]{policyID}, EntitlementConstants.PolicyPublish.ACTION_CREATE, null, true, 0);

            Thread.sleep(2000);
            PaginatedStatusHolder paginatedStatusHolder = policyAdminStub.
                    getStatusData(EntitlementConstants.Status.ABOUT_POLICY, policyID, EntitlementConstants.StatusTypes.PUBLISH_POLICY, "*", 1);
            StatusHolder statusHolder = paginatedStatusHolder.getStatusHolders()[0];
            if(statusHolder.getSuccess() && EntitlementConstants.PolicyPublish.ACTION_CREATE.equals(statusHolder.getTargetAction())){
                System.out.println("INFO : Policy is published successfully");
                return policyID;
            } else {
                System.out.println("ERROR : Policy is failed to publish");
                return "ERROR : Policy is failed to publish";
            }            
        } 
        catch (Exception e) 
        {
            System.out.println("\nError :  " + e.getMessage());
            e.printStackTrace();
            authCookie = null;
            return "\nError :  " + e.getMessage();
        }
	}
	
	public String DeletePolicy(String policyID)
	{
        try {            
        	policyAdminStub.dePromotePolicy(policyID);
            Thread.sleep(2000);
            PaginatedStatusHolder paginatedStatusHolder = policyAdminStub.
                    getStatusData(EntitlementConstants.Status.ABOUT_POLICY, policyID, EntitlementConstants.StatusTypes.PUBLISH_POLICY, "*", 1);
            StatusHolder statusHolder = paginatedStatusHolder.getStatusHolders()[0];
            if(statusHolder.getSuccess() && EntitlementConstants.PolicyPublish.ACTION_DELETE.equals(statusHolder.getTargetAction())){
                policyAdminStub.removePolicy(policyID, false);
                System.out.println("INFO: Policy is deleted successfully");
                return "Policy is deleted successfully";
            } else {
                System.out.println("Error:  Policy is failed to delete");
                return "Error:  Policy is failed to delete";
            }            
        } 
        catch (Exception e) 
        {
            System.out.println("Error :  " + e.getMessage());
            e.printStackTrace();
            authCookie = null;
            return "Error: " + e.getMessage();
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
	
	public String exportPolicy(String roleID, String exportedRoleID)
	{
		PolicyDTO policyDTO = clonePolicyRole(roleID, exportedRoleID);
		if( policyDTO == null )
			return null;
		
		String response = CreatePolicy(policyDTO);		
		return response;
	}
	
	public PolicyDTO clonePolicyRole(String roleID, String exportedRoleID)
	{
		PolicyDTO policyDTO = getPolicyByRole(roleID);
		if( policyDTO == null )
			return null;
				
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
		
		//Permissions filter

    	Random r = new Random();
    	int id = r.nextInt();
        String newPolicyID = "DynamicPolicy" + Integer.toString(id);
		String policyString = getTemplatePolicy(newPolicyID, exportedRoleID, permissions);
		PolicyDTO newPolicy = new PolicyDTO();
		newPolicy.setPolicyId(newPolicyID);
		newPolicy.setPolicy(policyString);
		return newPolicy;
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
	
	public int deleteAllDynamicPolicies()
	{
        try {   
        	int count = 0;
        	String[] policies = policyAdminStub.getAllPolicyIds("");
        	for( String policyID : policies )
        	{
        		if( policyID.startsWith("DynamicPolicy"))
        		{
            		System.out.println("Deletar:" + policyID);
        			DeletePolicy(policyID);
        			count++;
        		}
        	}
            
            return count;
        } 
        catch (Exception e) 
        {
            System.out.println("\nError :  " + e.getMessage());
            e.printStackTrace();
            authCookie = null;
            return -1;
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
						"            <AttributeDesignator AttributeId=\"wallet_active_role\" Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"true\"></AttributeDesignator>"+
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
}
