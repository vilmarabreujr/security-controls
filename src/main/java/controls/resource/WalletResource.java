package controls.resource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import controls.domains.Domain;
import controls.domains.DomainController;
import controls.openid.TokenValidationService;
import controls.rbac.Controller;
import controls.rbac.ExportedRole;
import controls.rbac.Role;
import controls.rbac.Session;
import controls.rbac.User;
import controls.response.TokenValidationResponse;
import controls.xacml.PolicyManager;
import crypto.RSA;
import util.AuthProperties;

@Path("wallet")
public class WalletResource {
	private static Map<Domain, PolicyManager> policyManagers;
	public WalletResource() throws Exception {				
		if( policyManagers == null )
		{
			policyManagers = new HashMap<Domain, PolicyManager>();
			DomainController domains = DomainController.getInstance();
			for( Domain d : domains.getDomains() )
			{
				PolicyManager controllerRBAC = new PolicyManager(d);
				policyManagers.put(d, controllerRBAC);
			}
			
		}
	}

	private PolicyManager getPolicyManager(HttpServletRequest httpRequest)
	{
		DomainController controller = DomainController.getInstance();
    	Domain d = controller.getDomain(httpRequest);
    	if( d == null )
    		return null;
    	PolicyManager policyManager = policyManagers.get(d);
		return policyManager;
	}
	

	@GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getExportedRoles(@QueryParam("accessToken") String token, @QueryParam("domain") String domain,@Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid","invalid")).build();
            
            DomainController domainController = DomainController.getInstance();
            Domain externalDomain = domainController.getDomain(domain);
			if( externalDomain == null )
			{
	            return Response.ok("{\"error\": \"The domain is not trustable.\"}").build();
			}
            Controller controllerRBAC = RBACResource.getInst().getControllerRBAC(httpRequest);
            
			List<ExportedRole> exportedRoles = controllerRBAC.getExportedRole(domain);

			String response = "{\"exportedroles\": [";
			for( int i = 0; i < exportedRoles.size(); i++ )
			{
				Role role = exportedRoles.get(i);
				response += role.toString();
				//se nao for o ultimo
				if( i < exportedRoles.size() -1 )
					response += ", ";
			}	
			response += "]}";
			System.out.println(response);
			//response = new String(RSA.encrypt(response, externalDomain.getPublicKey()));	

            return Response.ok(response).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
	
	@POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response exportRole(@QueryParam("accessToken") String token, @QueryParam("role") String originalRole, @QueryParam("domain") String domain, @QueryParam("registerdRole") String registerdRole,@Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid","invalid")).build();
            
            String subject = service.getSubject();
            Controller controllerRBAC = RBACResource.getInst().getControllerRBAC(httpRequest);
            User u = controllerRBAC.getUser(subject);
			if( u == null )
			{
                return Response.ok("{\"error\": \"Invalid subject\"}").build();
			}		

			Session s = controllerRBAC.getSession(subject);
			Role activeRole = controllerRBAC.getRole(originalRole);
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
			String exportedRoleID = controllerRBAC.CreateExportedRole(originalRole, registerdRole, domain);
					
			if( exportedRoleID == null )
			{
	            return Response.ok("{\"error\": \"The exported role cannot be created.\"}").build();
			}
			//Exportar a politica
			PolicyManager policyManager = getPolicyManager(httpRequest);
			String policyID = policyManager.exportPolicy(originalRole, exportedRoleID);
			if( policyID == null )
			{
	            return Response.ok("{\"error\": \"\"Error: There is no policy associated with the \"" + originalRole +"\"}").build();
			}

            return Response.ok("{\"sucess\": \"The policy has been exported!\", \"policy\": \"" + policyID + "\", \"role\": \"" + exportedRoleID + "\"}").build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
    
	
	@GET
    @Path("registered")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRegisteredRoles(@QueryParam("accessToken") String token, @Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid","invalid")).build();
            
            Controller controllerRBAC = RBACResource.getInst().getControllerRBAC(httpRequest);
            
			List<Role> roles = controllerRBAC.getRegisterRole();

			String response = "{\"registeredroles\": [";
			for( int i = 0; i < roles.size(); i++ )
			{
				Role role = roles.get(i);
				response += role.toString();
				//se nao for o ultimo
				if( i < roles.size() -1 )
					response += ", ";
			}	
			response += "]}";

            return Response.ok(response).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
	
	@POST
    @Path("registered")
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerRole(@QueryParam("accessToken") String token, @QueryParam("role") String role, @Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid","invalid")).build();
            
            String subject = service.getSubject();
            Controller controllerRBAC = RBACResource.getInst().getControllerRBAC(httpRequest);
            User u = controllerRBAC.getUser(subject);
			if( u == null )
			{
                return Response.ok("{\"error\": \"Invalid subject\"}").build();
			}		

			Role registeredRole = controllerRBAC.getRole(role);
			if( registeredRole == null )
			{
	            return Response.ok("{\"error\": \"Invalid role.\"}").build();
			}
			
			//Criar um papel temporario
			boolean process = controllerRBAC.setRegisterRole(registeredRole, true);
						
			if( process == false )
			{
	            return Response.ok("{\"error\": \"The role cannot be registered.\"}").build();
			}

            return Response.ok("{\"sucess\": \"The role has been registered!\"}").build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }

}
