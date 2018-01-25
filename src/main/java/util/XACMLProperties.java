package util;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import controls.domains.Domain;

public class XACMLProperties 
{
    private String PROPS_FILE = "xacml.prp";
    public final String TRUST_STORE_PATH = "trustStore";
    public final String TRUST_STORE_PASSWORD = "trustStorePassword";
    public final String SERVER_URL = "identityServerUrl";
    public final String SERVER_USER_NAME = "identityServerUsername";
    public final String SERVER_PASSWORD = "identityServerPassword";
    public final String POLICY_PATH = "policyPath";	
    public final String DOMAIN = "domain";	
	
	private String TrustStore;
	private String TrustStorePassword;
	private String ServerUrl;
	private String ServerUsername;
	private String ServerPassword;
	private String Domain;
	
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
    
    public String getDomain(){
        return Domain;
    }
    
    private XACMLProperties(String path) {
        path = path + PROPS_FILE;
        loadConfigProperties(path);
    }
    
    public static XACMLProperties init(Domain d){
        return new XACMLProperties(d.getConfigPath());
    }
    
    public void loadConfigProperties(String file) {
        try 
        {
            if(file != null)
            {
                Properties properties = new Properties();
                properties.load(new FileInputStream(file));
                if(properties != null  && properties.getProperty(TRUST_STORE_PATH) != null)
                {
                    this.TrustStore = properties.getProperty(TRUST_STORE_PATH);
                }
                if(properties != null  && properties.getProperty(TRUST_STORE_PASSWORD) != null)
                {
                    this.TrustStorePassword = properties.getProperty(TRUST_STORE_PASSWORD);
                }
                if(properties != null  && properties.getProperty(SERVER_URL) != null)
                {
                    this.ServerUrl = properties.getProperty(SERVER_URL);
                }
                if(properties != null  && properties.getProperty(SERVER_USER_NAME) != null)
                {
                    this.ServerUsername = properties.getProperty(SERVER_USER_NAME);
                }
                if(properties != null  && properties.getProperty(SERVER_PASSWORD) != null)
                {
                    this.ServerPassword = properties.getProperty(SERVER_PASSWORD);
                }
                if(properties != null  && properties.getProperty(DOMAIN) != null)
                {
                    this.Domain = properties.getProperty(DOMAIN);
                }
            }
        } 
        catch (IOException e) {
            String msg = "Error loading properties from xacml.prp file";
            System.out.println(msg);
        } 
    }

}
