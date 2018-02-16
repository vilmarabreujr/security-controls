package controls.resource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.DELETE;
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
import controls.response.TokenValidationResponse;
import util.AuthProperties;
import controls.rbac.*;

@Path("rbac")
public class RBACResource 
{
	private static Map<Domain, Controller> controllers;

	public Controller getControllerRBAC(HttpServletRequest httpRequest)
	{
		DomainController controller = DomainController.getInstance();
    	Domain d = controller.getDomain(httpRequest);
    	if( d == null )
    		return null;
    	Controller controllerRBAC = controllers.get(d);
		return controllerRBAC;
	}
	
	public static RBACResource inst;
	

	public static RBACResource getInst()
	{
		if( inst == null )
		{
			inst = new RBACResource();
		}
		return inst;
	}
	
	public RBACResource() {
		if( controllers == null )
		{
			controllers = new HashMap<Domain, Controller>();
			DomainController domains = DomainController.getInstance();
			for( Domain d : domains.getDomains() )
			{
				Controller controllerRBAC = new Controller(d);
				controllers.put(d, controllerRBAC);
			}
			
		}
	}
	
	@GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAvaliableRoles(@QueryParam("accessToken") String token,@Context HttpServletRequest httpRequest) {		
		
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid","invalid")).build();
            
            String subject = service.getSubject();
            Controller controllerRBAC = getControllerRBAC(httpRequest);
            
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

			String response = "{\"roles\": [";
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
	
    @GET
    @Path("activated")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getActivateRoles(@QueryParam("accessToken") String token,@Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid","invalid")).build();
            
            String subject = service.getSubject();

            Controller controllerRBAC = getControllerRBAC(httpRequest);
            User u = controllerRBAC.getUser(subject);
			if( u == null )
			{
                return Response.ok("{\"error\": \"Invalid subject\"}").build();
			}

			Session s = controllerRBAC.getSession(subject);
			
			String response = "{\"activeroles\": [";
			if( s != null )
			{
				for( int i = 0; i < s.getListRoles().size(); i++ )
				{
					Role role = s.getListRoles().get(i);
					response += role.toString();
					//se nao for o ultimo
					if( i < s.getListRoles().size() -1 )
						response += ", ";
				}	
			}
			response += "]}";

            return Response.ok(response).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
    
    @POST
    @Path("activated")
    @Produces(MediaType.APPLICATION_JSON)
    public Response AddActiveRole(@QueryParam("accessToken") String token, @QueryParam("role") String roleID,@Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid","invalid")).build();
            
            String subject = service.getSubject();

            Controller controllerRBAC = getControllerRBAC(httpRequest);
            User u = controllerRBAC.getUser(subject);
			if( u == null )
			{
                return Response.ok("{\"error\": \"Invalid subject\"}").build();
			}

			Session s = controllerRBAC.getSession(subject);
			
			if( s == null )
			{
				if( !controllerRBAC.CreateSession(subject) )
				{
					String response = "{\"error\": \"Can't create session for this subject\"}";
		            return Response.ok(response).build();
				}
			}
			String response = controllerRBAC.AddActiveRole(subject, roleID);
            return Response.ok(response).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
    
    @DELETE
    @Path("activated")
    @Produces(MediaType.APPLICATION_JSON)
    public Response DropActiveRole(@QueryParam("accessToken") String token, @QueryParam("role") String roleID,@Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid","invalid")).build();
            
            String subject = service.getSubject();

            Controller controllerRBAC = getControllerRBAC(httpRequest);
            User u = controllerRBAC.getUser(subject);
			if( u == null )
			{
                return Response.ok("{\"error\": \"Invalid subject\"}").build();
			}

			Session s = controllerRBAC.getSession(subject);
			if( s == null )
			{
			    return Response.ok("{\"error\": \"Subject haven't a session\"}").build();
			}
			if( !controllerRBAC.DropActiveRole(subject, roleID) )
			{
			    return Response.ok("{\"sucess\": \"Can't desactivate this role.\"}").build();
			}
            return Response.ok("{\"sucess\": \"Role desactivated!\"}").build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
    
    @GET
    @Path("constraints")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConstraints(@QueryParam("accessToken") String token,@Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid","invalid")).build();
            
            String subject = service.getSubject();

            Controller controllerRBAC = getControllerRBAC(httpRequest);
            User u = controllerRBAC.getUser(subject);
			if( u == null )
			{
                return Response.ok("{\"error\": \"Invalid subject\"}").build();
			}
			
			String response = "{\"constraints\": [";
			for( int i = 0; i < controllerRBAC.getDynamicConstraints().size(); i++ )
			{
				Constraint current = controllerRBAC.getDynamicConstraints().get(i);
				response += current.toString();
				//se nao for o ultimo
				if( i < controllerRBAC.getDynamicConstraints().size() -1 )
					response += ", ";
			}
			response += "]}";

            return Response.ok(response).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
    
    @POST
    @Path("constraints")
    @Produces(MediaType.APPLICATION_JSON)
    public Response AddDynamicSepartionOfDuty(@QueryParam("accessToken") String token, @QueryParam("roleA") String roleA, @QueryParam("roleB") String roleB,@Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid","invalid")).build();
            
            String subject = service.getSubject();

            Controller controllerRBAC = getControllerRBAC(httpRequest);
            User u = controllerRBAC.getUser(subject);
			if( u == null )
			{
                return Response.ok("{\"error\": \"Invalid subject\"}").build();
			}
			
			if( !controllerRBAC.AddDynamicSepartionOfDuty(roleA, roleB) )
			{
	            return Response.ok("{\"error\": \"Can't create SoD between this roles\"}").build();
			}
			else
			{
	            return Response.ok("{\"sucess\": \"SoD created!\"}").build();
			}

            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
    
    @DELETE
    @Path("constraints")
    @Produces(MediaType.APPLICATION_JSON)
    public Response RemoveDynamicSepartionOfDuty(@QueryParam("accessToken") String token, @QueryParam("roleA") String roleA, @QueryParam("roleB") String roleB,@Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid","invalid")).build();
            
            String subject = service.getSubject();

            Controller controllerRBAC = getControllerRBAC(httpRequest);
            User u = controllerRBAC.getUser(subject);
			if( u == null )
			{
                return Response.ok("{\"error\": \"Invalid subject\"}").build();
			}
			
			if( !controllerRBAC.RemoveDynamicSepartionOfDuty(roleA, roleB) )
			{
	            return Response.ok("{\"error\": \"Can't remove SoD\"}").build();
			}
			else
			{
	            return Response.ok("{\"sucess\": \"SoD removed!\"}").build();
			}

            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
    
}
