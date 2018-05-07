package config;

import javax.ws.rs.ApplicationPath;

import org.glassfish.jersey.server.ResourceConfig;

@ApplicationPath("eletrobras")
public class EletrobrasConfig extends ResourceConfig {

    public EletrobrasConfig() {
        packages("com.fasterxml.jackson.jarxrs.json");
        packages("controls.resource");
    }
}