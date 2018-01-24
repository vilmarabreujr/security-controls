package controls.resource;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
public class MainResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response welcome() {    	
        try {
    	    String response = "Security Controls";
            return Response.ok(response).build(); 
        } catch (Exception e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e).build();
        }
    }
}
