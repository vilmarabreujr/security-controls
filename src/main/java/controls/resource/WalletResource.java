package controls.resource;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import controls.domains.DomainController;
import controls.openid.TokenValidationService;
import controls.rbac.Controller;
import controls.rbac.Role;
import controls.rbac.Session;
import controls.rbac.User;
import controls.response.TokenValidationResponse;
import controls.xacml.PolicyManager;

@Path("wallet")
public class WalletResource {
	private static PolicyManager policyManager;
	public WalletResource() throws Exception {		
		if( policyManager == null )
		{
			policyManager = new PolicyManager();
		}
	}

	@GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getExportedRoles(@QueryParam("accessToken") String token) {
        TokenValidationService service = new TokenValidationService();
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid")).build();
            
            String subject = service.getSubject();
            subject = subject.replace("@carbon.super", "");

            Controller controllerRBAC = RBACResource.getControllerRBAC();
            User u = controllerRBAC.getUser(subject);
			if( u == null )
			{
                return Response.ok("{\"error\": \"Invalid subject\"}").build();
			}

			Session s = controllerRBAC.getSession(subject);
			List<Role> ActiveRoles = new ArrayList<Role>();
			List<Role> AvaliableRoles = new ArrayList<Role>();
			if( s != null )
			{
				ActiveRoles = s.getListRoles();
			}
			
			for( int i = 0; i < u.getRoles().size(); i++ )
			{
				Role role = u.getRoles().get(i);
				if( !ActiveRoles.contains(role) )
				{
					AvaliableRoles.add(role);
				}
			}	

			String response = "{\"exportedroles\": [";
			for( int i = 0; i < AvaliableRoles.size(); i++ )
			{
				Role role = AvaliableRoles.get(i);
				response += role.toString();
				//se nao for o ultimo
				if( i < AvaliableRoles.size() -1 )
					response += ", ";
			}
			response += "]}";

            return Response.ok(response).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
	
	@POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response exportRole(@QueryParam("accessToken") String token, @QueryParam("role") String role, @QueryParam("domain") String domain) {
        TokenValidationService service = new TokenValidationService();
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid")).build();
            
            String subject = service.getSubject();
            subject = subject.replace("@carbon.super", "");
            Controller controllerRBAC = RBACResource.getControllerRBAC();
            User u = controllerRBAC.getUser(subject);
			if( u == null )
			{
                return Response.ok("{\"error\": \"Invalid subject\"}").build();
			}		

			Session s = controllerRBAC.getSession(subject);
			Role activeRole = controllerRBAC.getRole(role);
			if( activeRole == null )
			{
	            return Response.ok("{\"error\": \"Invalid role.\"}").build();
			}
			if( !s.getListRoles().contains(activeRole) )
			{
	            return Response.ok("{\"error\": \"The exported role must be activated.\"}").build();
			}
			//Verificar se é um domínio valido
			DomainController domainController = DomainController.getInstance();
			if( !domainController.isTrustDomain(domain) )
			{
	            return Response.ok("{\"error\": \"The domain is not trustable.\"}").build();
			}
			//Conferir as permissões
			
			//Criar um papel temporario
			String exportedRoleID = controllerRBAC.CreateExportedRole(domain);
			if( exportedRoleID == null )
			{
	            return Response.ok("{\"error\": \"The exported role cannot be created.\"}").build();
			}
			//Exportar a politica
			String policyID = policyManager.exportPolicy(role, exportedRoleID);
			if( policyID == null )
			{
	            return Response.ok("{\"error\": \"\"Error: There is no policy associated with the \"" + role +"\"}").build();
			}

            return Response.ok("{\"sucess\": \"The policy has been exported!\", \"policy\": \"" + policyID + "\", \"role\": \"" + exportedRoleID + "\"}").build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
    

}
