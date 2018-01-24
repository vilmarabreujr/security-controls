package config;

import javax.ws.rs.ApplicationPath;

import org.glassfish.jersey.server.ResourceConfig;

@ApplicationPath("furnas")
public class FurnasConfig extends ResourceConfig {

    public FurnasConfig() {
        packages("com.fasterxml.jackson.jarxrs.json");
        packages("controls.resource");
    }
}