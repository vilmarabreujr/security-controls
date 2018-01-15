package controls.xacml;


import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.wso2.carbon.identity.entitlement.common.EntitlementConstants;
import org.wso2.carbon.identity.entitlement.stub.EntitlementPolicyAdminServiceStub;
import org.wso2.carbon.identity.entitlement.stub.dto.PaginatedStatusHolder;
import org.wso2.carbon.identity.entitlement.stub.dto.PolicyDTO;
import org.wso2.carbon.identity.entitlement.stub.dto.StatusHolder;

import java.io.File;

/**
 *  This is sample code that shows how you can automate the EntitlementPolicyAdminService web service API.
 *  This API can be used to upload, update, delete and publish PAP policies.
 *
 */
public class PolicyTester {
	
	static {
	    //for localhost testing only
	    javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
	    new javax.net.ssl.HostnameVerifier(){
 
	        public boolean verify(String hostname,
	                javax.net.ssl.SSLSession sslSession) {
	            if (hostname.equals("domain-a") || hostname.equals("domain-b") || hostname.equals("domain-c")) {
	                return true;
	            }
	            return false;
	        }
	    });
	}

    public static final String SERVER_URL = "https://localhost:9444/services/EntitlementPolicyAdminService";
    public static final String SERVER_USER_NAME = "admin";
    public static final String SERVER_PASSWORD = "admin";

    public static void main (String[] args) throws Exception {

    	PolicyManager manager = new PolicyManager();
    	String s = manager.clonePolicyRole("doutorando");
        System.out.println(s);

    }

    private static String readPolicy(){

        return "<Policy xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" PolicyId=\"SamplePolicy\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable\" Version=\"1.0\">\n" +
                "   <Target>\n" +
                "      <AnyOf>\n" +
                "         <AllOf>\n" +
                "            <Match MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\">\n" +
                "               <AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">echo</AttributeValue>\n" +
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
                "                  <AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">read</AttributeValue>\n" +
                "                  <AttributeDesignator AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\" Category=\"urn:oasis:names:tc:xacml:3.0:attribute-category:action\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"true\"/>\n" +
                "               </Match>\n" +
                "            </AllOf>\n" +
                "         </AnyOf>\n" +
                "      </Target>\n" +
                "      <Condition>\n" +
                "         <Apply FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:any-of\">\n" +
                "            <Function FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\"/>\n" +
                "            <AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#string\">asela</AttributeValue>\n" +
                "            <AttributeDesignator AttributeId=\"urn:oasis:names:tc:xacml:1.0:subject:subject-id\" Category=\"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject\" DataType=\"http://www.w3.org/2001/XMLSchema#string\" MustBePresent=\"true\"/>\n" +
                "         </Apply>\n" +
                "      </Condition>\n" +
                "   </Rule>\n" +
                "   <Rule Effect=\"Deny\" RuleId=\"Deny-Rule\"/>\n" +
                "</Policy> ";
    }
}