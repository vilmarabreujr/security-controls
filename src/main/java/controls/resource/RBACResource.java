package controls.resource;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.amber.oauth2.common.exception.OAuthSystemException;

import controls.openid.AuthenticationService;
import controls.openid.TokenValidationService;
import controls.response.GetUriResponse;
import controls.response.TokenValidationResponse;
import rbac.Role;
import controls.rbac.*;
import util.XACMLProperties;

@Path("rbac")
public class RBACResource {
	private static Controller controllerRBAC;
	
	public RBACResource() {
		if( controllerRBAC == null )
		{
			controllerRBAC = new Controller();
			XACMLProperties properties = XACMLProperties.inst();
			controllerRBAC.LoadWSo2(properties.getServerUrl() + "RemoteUserStoreManagerService", properties.getServerUsername(), properties.getServerPassword());
		}
	}

	@GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRoles(@QueryParam("token") String token) {
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
    public Response getActivatedRoles(@QueryParam("token") String token) {
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
			
			/*resp.getWriter().append("{\"roles\": [");
			if( s != null )
			{
				for( int i = 0; i < s.getListRoles().size(); i++ )
				{
					Role role = s.getListRoles().get(i);
					resp.getWriter().append(role.toString());
					//se nao for o ultimo
					if( i < s.getListRoles().size() -1 )
						resp.getWriter().append(", ");
				}	
			}
			resp.getWriter().append("]}");*/

            return Response.ok(response).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }
}
