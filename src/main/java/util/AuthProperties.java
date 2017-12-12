package util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class AuthProperties {

    /**
     * If you want your conf.prp file in a different location please update 
     * it here and in the method initPrtopsFileLocation()
     */
    private static String PROPS_FILE = "/.wso2Example/conf.prp";

    private static AuthProperties inst;

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

    private AuthProperties() {
        initPropsFileLocation();
        initProperties();
    }

    public static AuthProperties inst() {
        if (inst == null)
            inst = new AuthProperties();

        return inst;
    }
    
    private void initPropsFileLocation() {
        String homeDir = System.getenv("HOME");
        PROPS_FILE = homeDir + PROPS_FILE;
    }
    
    private void initProperties() {
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

}
