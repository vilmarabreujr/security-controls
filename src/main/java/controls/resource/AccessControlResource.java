package controls.resource;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;

import controls.openid.AuthorizationService;
import controls.response.AuthorizationResponse;
import controls.xacml.ContextHandler;

@Path("access-control")
public class AccessControlResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response authorizate(@QueryParam("accessToken") String token,
                                    @QueryParam("resource") String resource,
                                    @QueryParam("action") String action) {
    	
        try {

            ContextHandler contextHandler = new ContextHandler();
        	if( !contextHandler.ValidateRequest(token, resource, action) )
    		{
                return Response.ok("{\"sucess\": \"Access denied!\"}").build();
    		}	
    		else
    		{
                return Response.ok("{\"sucess\": \"Access allowed!\"}").build();
    		}  

        } catch (Exception e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e).build();
        }
    }

    

}
