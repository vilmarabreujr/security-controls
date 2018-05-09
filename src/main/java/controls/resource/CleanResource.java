package controls.resource;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("clear")
public class CleanResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response welcome() {    	
        try {
        	System.out.println("Initing RBAC domains");
        	RBACResource r = RBACResource.getInst();
        	System.out.println("Initing Policy domains");
        	WalletResource w = WalletResource.getInst();
        	System.out.println("Deleting dynamic policies");
        	int c = w.deleteAllDynamicPolicies();
        	System.out.println("Deleted policies: " + c);      
    	    String response = "Resource is cleared!";
            return Response.ok(response).build(); 
        } catch (Exception e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e).build();
        }
    }
}
