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

@Path("authorizate")
public class AuthorizationResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response authorizate(@QueryParam("authorizationToken") String authToken,
                                    @QueryParam("callbackUri") String callbackUri) {

        AuthorizationService service = new AuthorizationService();
        
        try {

            String accessToken = service.requestAccessToken(authToken, callbackUri);
            String idToken = service.getCurrentIDToken();
            return Response.ok(new AuthorizationResponse(accessToken, idToken)).build();

        } catch (OAuthSystemException | OAuthProblemException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e).build();
        }
    }

    

}
