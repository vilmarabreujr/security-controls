package controls.resource;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import controls.openid.TokenValidationService;
import controls.response.TokenValidationResponse;
import controls.rbac.*;

@Path("rbac")
public class RBACResource {
	private static Controller controllerRBAC;

	public static Controller getControllerRBAC()
	{
		return controllerRBAC;
	}
	
	public RBACResource() {
		if( controllerRBAC == null )
		{
			controllerRBAC = new Controller(true);
		}
	}

	@GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAvaliableRoles(@QueryParam("accessToken") String token) {
        TokenValidationService service = new TokenValidationService();
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid")).build();
            
            String subject = service.getSubject();
            subject = subject.replace("@carbon.super", "");
            
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
    public Response getActivateRoles(@QueryParam("accessToken") String token) {
        TokenValidationService service = new TokenValidationService();
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid")).build();
            
            String subject = service.getSubject();
            subject = subject.replace("@carbon.super", "");
            
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
    public Response AddActiveRole(@QueryParam("accessToken") String token, @QueryParam("role") String roleID) {
        TokenValidationService service = new TokenValidationService();
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid")).build();
            
            String subject = service.getSubject();
            subject = subject.replace("@carbon.super", "");
            
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
    public Response DropActiveRole(@QueryParam("accessToken") String token, @QueryParam("role") String roleID) {
        TokenValidationService service = new TokenValidationService();
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid")).build();
            
            String subject = service.getSubject();
            subject = subject.replace("@carbon.super", "");
            
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
    public Response getConstraints(@QueryParam("accessToken") String token) {
        TokenValidationService service = new TokenValidationService();
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid")).build();
            
            String subject = service.getSubject();
            subject = subject.replace("@carbon.super", "");
            
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
    public Response AddDynamicSepartionOfDuty(@QueryParam("accessToken") String token, @QueryParam("roleA") String roleA, @QueryParam("roleB") String roleB) {
        TokenValidationService service = new TokenValidationService();
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid")).build();
            
            String subject = service.getSubject();
            subject = subject.replace("@carbon.super", "");
            
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
    public Response RemoveDynamicSepartionOfDuty(@QueryParam("accessToken") String token, @QueryParam("roleA") String roleA, @QueryParam("roleB") String roleB) {
        TokenValidationService service = new TokenValidationService();
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid")).build();
            
            String subject = service.getSubject();
            subject = subject.replace("@carbon.super", "");
            
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
