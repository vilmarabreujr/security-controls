package util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;

import controls.domains.Domain;
import controls.domains.DomainController;
import controls.rbac.Controller;

public class AuthProperties {

    /**
     * If you want your conf.prp file in a different location please update 
     * it here and in the method initPrtopsFileLocation()
     */

    private String scope;
    private String authzEndpoint;
    private String tokenEndpoint;
    private String logoutEndpoint;
    private String userInformationEndpoint;
    private String tokenValidationEndpoint;
    
    private String wso2User;
    private String wso2Password;
    private String serviceProviderName;
    
    private String consumerKey;
    private String consumerSecret;
    private String callBackURL;
    private String securityControlsURL;

    private AuthProperties(String file) {
        String path = initPropsFileLocation(file);
        initProperties(path);
    }
    
    public static AuthProperties init(Domain d) {
    	String file = d.getConfigPath();
        return new AuthProperties(file);
    }
    
    public static AuthProperties init(HttpServletRequest httpRequest) {
		DomainController controller = DomainController.getInstance();
    	Domain d = controller.getDomain(httpRequest);
    	if( d == null )
    		return null;
        return init(d);
    }
    
    public static AuthProperties init() {
		String file = "/home/aluno/.wso2/";
        return new AuthProperties(file);
    }
    
    private String initPropsFileLocation(String file) {
        file = file + "conf.prp";
        return file;
    }
    
    private void initProperties(String PROPS_FILE) {
        Properties props = new Properties();

        try {
            props.load(new FileInputStream(PROPS_FILE));

            scope = props.getProperty("scope");
            authzEndpoint = props.getProperty("authzEndpoint");
            tokenEndpoint = props.getProperty("tokenEndpoint");
            logoutEndpoint = props.getProperty("logoutEndpoint");
            userInformationEndpoint = props.getProperty("userInformationEndpoint");
            tokenValidationEndpoint = props.getProperty("tokenValidationEndpoint");
            
            wso2User = props.getProperty("wso2User");
            wso2Password = props.getProperty("wso2Password");
            serviceProviderName = props.getProperty("serviceProviderName");
            
            consumerKey = props.getProperty("consumerKey");
            consumerSecret = props.getProperty("consumerSecret");
            callBackURL = props.getProperty("callBackURL");
            securityControlsURL = props.getProperty("securityControlsURL");

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getScope() {
        return scope;
    }

    public String getAuthzEndpoint() {
        return authzEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }
    
    public String getLogoutEndpoint() {
        return logoutEndpoint;
    }

    public String getUserInformationEndpoint() {
        return userInformationEndpoint;
    }
    
    public String getTokenValidationEndpoint() {
        return tokenValidationEndpoint;
    }

    public String getServiceProviderName() {
        return serviceProviderName;
    }
    
    public String getWso2User() {
        return wso2User;
    }

    public String getWso2Password() {
        return wso2Password;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public String getConsumerSecret() {
        return consumerSecret;
    }
    
    public String getCallBackURL() {
        return callBackURL;
    }
    public String getSecurityControlsURL() {
        return securityControlsURL;
    }
}
