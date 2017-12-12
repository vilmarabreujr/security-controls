package util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class XACMLProperties 
{
    private static String PROPS_FILE = "/.wso2Example/xacml.prp";
    public static final String TRUST_STORE_PATH = "trustStore";
    public static final String TRUST_STORE_PASSWORD = "trustStorePassword";
    public static final String SERVER_URL = "identityServerUrl";
    public static final String SERVER_USER_NAME = "identityServerUsername";
    public static final String SERVER_PASSWORD = "identityServerPassword";
    public static final String POLICY_PATH = "policyPath";	
    private static XACMLProperties inst;
	
	private String TrustStore;
	private String TrustStorePassword;
	private String ServerUrl;
	private String ServerUsername;
	private String ServerPassword;
	
    public String getTrustStore() {
    	return TrustStore;
    }

    public String getTrustStorePassword(){
        return TrustStorePassword;
    }

    public String getServerUrl(){
        return ServerUrl;
    }

    public String getServerUsername(){
        return ServerUsername;
    }

    public String getServerPassword(){
        return ServerPassword;
    }
    
    private XACMLProperties() {
        String homeDir = System.getenv("HOME");
        PROPS_FILE = homeDir + PROPS_FILE;
        loadConfigProperties(PROPS_FILE);
    }
    
    public static XACMLProperties inst(){
        if (inst == null)
            inst = new XACMLProperties();

        return inst;
    }
    
    public void loadConfigProperties(String file) {
        try 
        {
            if(file != null)
            {
                Properties properties = new Properties();
                properties.load(new FileInputStream(file));
                if(properties != null  && properties.getProperty(XACMLProperties.TRUST_STORE_PATH) != null)
                {
                    this.TrustStore = properties.getProperty(XACMLProperties.TRUST_STORE_PATH);
                }
                if(properties != null  && properties.getProperty(XACMLProperties.TRUST_STORE_PASSWORD) != null)
                {
                    this.TrustStorePassword = properties.getProperty(XACMLProperties.TRUST_STORE_PASSWORD);
                }
                if(properties != null  && properties.getProperty(XACMLProperties.SERVER_URL) != null)
                {
                    this.ServerUrl = properties.getProperty(XACMLProperties.SERVER_URL);
                }
                if(properties != null  && properties.getProperty(XACMLProperties.SERVER_USER_NAME) != null)
                {
                    this.ServerUsername = properties.getProperty(XACMLProperties.SERVER_USER_NAME);
                }
                if(properties != null  && properties.getProperty(XACMLProperties.SERVER_PASSWORD) != null)
                {
                    this.ServerPassword = properties.getProperty(XACMLProperties.SERVER_PASSWORD);
                }
            }
        } 
        catch (IOException e) {
            String msg = "Error loading properties from xacml.prp file";
            System.out.println(msg);
        } 
    }

}
