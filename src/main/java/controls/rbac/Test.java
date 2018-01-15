package controls.rbac;

import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;

public class Test {

	public static void main(String[] args) 
	{
		// TODO Auto-generated method stub
		Controller controller = new Controller(false);
		controller.LoadWSo2("https://localhost:9444/services/RemoteUserStoreManagerService", "admin", "admin");

		User u = controller.getUser("vilmar");
		if( controller.CreateSession(u.getId()) )
			System.out.println("Sessao criada");
		
		System.out.println("Papeis disponiveis");
		for(int i = 0; i < u.getRoles().size(); i++ )
		{
			System.out.println("---" + u.getRoles().get(i).getId());
		}		
		
		/*if( u.getRoles().size() > 0 )
		{
			String us = u.getId();
			String r = u.getRoles().get(0).getId();
			if( controller.AddActiveRole(us, r) )
			{
				System.out.println("Papel " + r + " ativado para o usuario " + us);
			}
			else
			{
				System.out.println("Nao foi possivel ativar o papel " + r + " para o usuario " + us);
			}
		}*/
	}


}
