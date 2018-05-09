package config;

import javax.ws.rs.ApplicationPath;

import org.glassfish.jersey.server.ResourceConfig;

@ApplicationPath("init")
public class InitConfig extends ResourceConfig {

    public InitConfig() {
        packages("com.fasterxml.jackson.jarxrs.json");
        packages("controls.resource");
    }
}