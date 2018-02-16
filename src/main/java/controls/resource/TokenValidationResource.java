package controls.resource;

import java.rmi.RemoteException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import controls.openid.TokenValidationService;
import controls.response.TokenValidationResponse;
import util.AuthProperties;

@Path("validate-token")
public class TokenValidationResource {


    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response authorizate(@QueryParam("accessToken") String accessToken,@Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {

            boolean isTokenValid = service.isTokenValid(accessToken);
            String subject = service.getSubject();
            String scope = service.getScope();
            return Response.ok(new TokenValidationResponse(isTokenValid,subject,scope)).build();

        } catch (RemoteException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e).build();
        }
    }
}
