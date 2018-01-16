package controls.rbac;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceStub;

import util.XACMLProperties;

public class Controller 
{
	private List<User> listUsers;
	private List<Role> listRoles;
	private List<Session> listSession;
	private List<Constraint> dynamicConstraints;
	private RemoteUserStoreManagerServiceStub adminStub;
	
	public Controller(boolean loadWSo2)
	{
		listUsers = new ArrayList<User>();
		listRoles = new ArrayList<Role>();
		listSession = new ArrayList<Session>();
		dynamicConstraints = new ArrayList<Constraint>();
		adminStub = null;

		if( loadWSo2 ) 
		{
			XACMLProperties properties = XACMLProperties.inst();
			LoadWSo2(properties.getServerUrl() + "RemoteUserStoreManagerService", properties.getServerUsername(), properties.getServerPassword());
		}
	}
	
	
	public List<Constraint> getDynamicConstraints()
	{
		return this.dynamicConstraints;
	}
	
	public User getUser(String user)
	{
		for( int i = 0; i < listUsers.size(); i++ )
		{
			User current = listUsers.get(i);
			if( user.equals(current.getId()) )
			{
				return current;
			}
		}
		return null;
	}
	
	public Session getSession(String user)
	{
		for( int i = 0; i < listSession.size(); i++ )
		{
			User current = listSession.get(i).getUser();
			if( user.equals(current.getId()) )
			{
				return listSession.get(i);
			}
		}
		return null;
	}
	
	public Role getRole(String role)
	{
		for( int i = 0; i < listRoles.size(); i++ )
		{
			Role current = listRoles.get(i);
			if( role.equals(current.getId()) )
			{
				return current;
			}
		}
		return null;
	}
		
	public void UserAssignment(User user, Role role)
	{
		//VERIFICAR O SOD ESTATICO NESSE PONTO
		user.addRole(role);
		role.addUser(user);
	}
	
	public boolean CheckUserAssignment(User user, Role role)
	{
		if( user == null )
			return false;
		if( role == null )
			return false;
		return user.getRoles().contains(role);
	}
	
	public void carregarStub(String serviceEndPoint, String adminUser, String adminPassword)
	{
		try 
        {
			if( adminStub == null )
			{
				ConfigurationContext configContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);
	            
	            adminStub = new RemoteUserStoreManagerServiceStub(configContext, serviceEndPoint);
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
	                auth.setUsername(adminUser);
	                auth.setPassword(adminPassword);
	                auth.setPreemptiveAuthentication(true);
	                option.setProperty(org.apache.axis2.transport.http.HTTPConstants.AUTHENTICATE, auth);
	            }
	            authCookie = (String) adminStub._getServiceClient().getServiceContext().getProperty(HTTPConstants.COOKIE_STRING);   
			}
        }
        catch (Exception e) 
        {
            System.out.println("\nError :  " + e.getMessage());
            e.printStackTrace();
        }
	}
	
	public boolean LoadWSo2(String serviceEndPoint, String adminUser, String adminPassword)
	{
        try 
        {
        	carregarStub(serviceEndPoint, adminUser, adminPassword);

            String[] users = adminStub.listUsers("*", 10000);
            for( int i = 0; i < users.length; i++ )
            {
            	String userString = users[i];
            	System.out.println(userString);
            	User user = new User(userString);
            	listUsers.add(user);
            	//Search user roles
            	String[] roles = adminStub.getRoleListOfUser(userString);
            	for( int j = 0; j < roles.length; j++ )
                {
                	String roleString = roles[j];
                	Role role = getRole(roleString);                	
                	if( role == null )
                	{
                		//New role
                		role = new Role(roleString);
                    	listRoles.add(role);
                	}
                	UserAssignment(user, role);
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
	
	public boolean AddRole(String roleName)
	{
		Role role = getRole(roleName);                	
    	if( role == null )
    	{
    		//New role
    		role = new Role(roleName);
        	listRoles.add(role);
    	}
		return true;
	}
	
	public boolean CreateSession(String userString)
	{
		User user = getUser(userString);
		if( user == null )
		{
			return false;
		}
		Session session = getSession(userString);
		if( session != null )
		{
			return false;
		}
		listSession.add(new Session(user));		
		return true;
	}
	
	public boolean DeleteSession(String userString)
	{
		User user = getUser(userString);
		if( user == null )
		{
			return false;
		}
		Session session = getSession(userString);
		if( session == null )
		{
			return false;
		}
		listSession.remove(session);		
		return true;
	}
	
	public String AddActiveRole(String userString, String roleString)
	{
		User user = getUser(userString);
		if( user == null )
		{
			return "{\"error\": \"Invalid subject.\"}";
		}
		Session session = getSession(userString);
		if( session == null )
		{
			return "{\"error\": \"Invalid session.\"}";
		}
		Role role = getRole(roleString);
		if( role == null )
		{
			return "{\"error\": \"Invalid role.\"}";
		}
		//Verificar se o usuário tem acesso ao papel
		if( !CheckUserAssignment(user, role) )
		{
			return "{\"error\": \"Subject haven't acess to this role.\"}";
		}
		//Verificar se o papel já foi ativado
		if( session.getListRoles().contains(role) )
		{
			return "{\"error\": \"Role already activate.\"}";
		}
		//VERIFICAR O SOD DINAMICO NESSE PONTO
		List<Role> activeRoles = session.getListRoles();
		for( int i = 0; i < activeRoles.size(); i++ )
		{
			Role active = activeRoles.get(i);
			if( isDynamicSepartionOfDuty(active, role) )
			{
				return "{\"error\": \"Can't activate this role, SoD with the role " + active.getId() + "\"}";
			}
		}		
		session.getListRoles().add(role);
		return "{\"sucess\": \"Role activated!\"}";
	}
	
	public boolean DropActiveRole(String userString, String roleString)
	{
		User user = getUser(userString);
		if( user == null )
		{
			return false;
		}
		Session session = getSession(userString);
		if( session == null )
		{
			return false;
		}
		Role role = getRole(roleString);
		if( role == null )
		{
			return false;
		}
		//Verificar se o usuário tem acesso ao papel
		if( !CheckUserAssignment(user, role) )
		{
			return false;
		}
		//Verificar se o papel esta ativado
		if( !session.getListRoles().contains(role) )
		{
			return false;
		}
		//VERIFICAR O SOD DINAMICO NESSE PONTO
		
		session.getListRoles().remove(role);
		return true;
	}
	
	public boolean AddDynamicSepartionOfDuty(String roleA, String roleB)
	{
		return AddDynamicSepartionOfDuty(getRole(roleA), getRole(roleB));
	}
	
	public boolean AddDynamicSepartionOfDuty(Role roleA, Role roleB)
	{
		if( roleA == null )
			return false;
		if( roleB == null )
			return false;
		if( roleA == roleB )
			return false;
		//Check if already exist
		if( isDynamicSepartionOfDuty(roleA, roleB) )
			return false;
		dynamicConstraints.add(new Constraint(roleA, roleB));
		return true;
	}
	
	public boolean RemoveDynamicSepartionOfDuty(String roleA, String roleB)
	{
		return RemoveDynamicSepartionOfDuty(getRole(roleA), getRole(roleB));
	}
	
	public boolean RemoveDynamicSepartionOfDuty(Role roleA, Role roleB)
	{
		if( roleA == null )
			return false;
		if( roleB == null )
			return false;
		if( roleA == roleB )
			return false;
		for( int i = 0; i < dynamicConstraints.size(); i++ )
		{
			Constraint current = dynamicConstraints.get(i);
			
			if( current.Exist(roleA, roleB) )
			{
				dynamicConstraints.remove(i);
				return true;
			}
			
		}		
		return false;
	}
	
	public boolean isDynamicSepartionOfDuty(Role roleA, Role roleB)
	{		
		//Check if already exist
		for( int i = 0; i < dynamicConstraints.size(); i++ )
		{
			Constraint current = dynamicConstraints.get(i);
			
			if( current.Exist(roleA, roleB) )
			{
				return true;
			}
			
		}
		return false;
	}
	
	public String CreateExportedRole(String domain)
	{
        try 
        {        	 
			//Criar papel
        	Random r = new Random();
        	int id = r.nextInt();
            String roleName = "DynamicRole" + Integer.toString(id);       

    		ExportedRole role = new ExportedRole(roleName, domain);
        	listRoles.add(role);
    		return roleName;         
        } 
        catch (Exception e) 
        {
            System.out.println("\nError :  " + e.getMessage());
            e.printStackTrace();
    		return null;
        }
	}

}
