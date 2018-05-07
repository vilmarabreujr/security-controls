package process;


import java.util.ArrayList;
import java.util.List;

import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceStub;

import controls.domains.Domain;
import controls.domains.DomainController;
import util.AuthProperties;

public class RegisterUsersDomain 
{
	private static String serviceEndPoint = "https://localhost:9443/services/RemoteUserStoreManagerService";
	public static AuthProperties prop;

	public static void main(String[] args) throws Exception
	{
		DomainController domains = DomainController.getInstance();
		
		String domainName = "eletrobras";
		Domain d = domains.getDomain(domainName);
		prop = AuthProperties.init(d);
		List<String> usuarios = RandomProcess.getUsers();
		CarregarUsuarios(usuarios);
	}	
	
	public static boolean CarregarUsuarios(List<String> todosUsuarios)
	{
        try 
        {
        	ConfigurationContext configContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);
            
            RemoteUserStoreManagerServiceStub adminStub = new RemoteUserStoreManagerServiceStub(configContext, serviceEndPoint);
            ServiceClient client = adminStub._getServiceClient();

            Options option = client.getOptions();
            option.setManageSession(true);
            String authCookie = null;
            option.setProperty(HTTPConstants.COOKIE_STRING, authCookie);            
            
            if( authCookie == null )
            {
                /**
                 * Setting basic auth headers for authentication for user admin
                 */
            	HttpTransportProperties.Authenticator auth = new HttpTransportProperties.Authenticator();
                auth.setUsername(prop.getWso2User());
                auth.setPassword(prop.getWso2Password());
                auth.setPreemptiveAuthentication(true);
                option.setProperty(org.apache.axis2.transport.http.HTTPConstants.AUTHENTICATE, auth);
            }
            authCookie = (String) adminStub._getServiceClient().getServiceContext().getProperty(HTTPConstants.COOKIE_STRING);   

            String[] users = adminStub.listUsers("*", 10000);
                        
            List<String> novosUsuarios = new ArrayList<String>();
            
            int MAXIMO_USUARIOS = 100;
            if( MAXIMO_USUARIOS > todosUsuarios.size() )
            	MAXIMO_USUARIOS = todosUsuarios.size();
                        
            for(int i = 0; i < MAXIMO_USUARIOS; i++)
            {
            	boolean existe = false;
            	String usuario = todosUsuarios.get(i);
            	for(int j = 0; j < users.length; j++)
                {
                	if( usuario.equals(users[j]) )
                	{
                		existe = true;
                		String[] papeis = adminStub.getRoleListOfUser(usuario);
            			
                		for( int k = 0; k < papeis.length; k++ )
                		{
                			System.out.print(papeis[k] + " - ");
                		}
                		System.out.println("");
                		
                		break;
                	}
                }
            	if( !existe )
            	{
            		novosUsuarios.add(usuario);
            	}
            }
            
            //Ligar com os papeis
            for( int i = 0; i < novosUsuarios.size(); i++ )
            {
            	String usuario = novosUsuarios.get(i);     
            	
            	if( !adminStub.isExistingUser(usuario) )
            	{
                    String[] Papeis = RandomProcess.getRandomRoles(3);
            		adminStub.addUser(usuario, "secret", Papeis,null,null,false);
            		System.out.println("usuario: " + usuario + " adicionado.");
            	}
            	else
            	{
            		System.out.println(usuario);
            	}
            	            		
            }
                        
    		return true;         
        } 
        catch (Exception e) 
        {
            System.out.println("\nError :  " + e.getMessage());
            e.printStackTrace();
    		return false;
        }
	}

}
