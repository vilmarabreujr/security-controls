package config;

import javax.ws.rs.ApplicationPath;

import org.glassfish.jersey.server.ResourceConfig;

@ApplicationPath("copel")
public class CopelConfig extends ResourceConfig {

    public CopelConfig() {
        packages("com.fasterxml.jackson.jarxrs.json");
        packages("controls.resource");
    }
}