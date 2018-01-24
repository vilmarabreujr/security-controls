package controls.resource;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
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

@Path("domain")
public class DomainResource {
	
	@GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTrustedDomains(@QueryParam("accessToken") String token,@Context HttpServletRequest httpRequest) {
        TokenValidationService service = new TokenValidationService(AuthProperties.init(httpRequest));
        
        try {
            boolean isTokenValid = service.isTokenValid(token);
            if( !isTokenValid )
                return Response.ok(new TokenValidationResponse(isTokenValid,"invalid")).build();
            
            DomainController domainController = DomainController.getInstance();
            
			String response = "{\"domains\": [";
			for( int i = 0; i < domainController.getDomains().size(); i++ )
			{
				Domain domain = domainController.getDomains().get(i);
				response += domain.toString();
				//se nao for o ultimo
				if( i < domainController.getDomains().size() -1 )
					response += ", ";
			}
			response += "]}";

            return Response.ok(response).build();
            
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
    }	
	
}
