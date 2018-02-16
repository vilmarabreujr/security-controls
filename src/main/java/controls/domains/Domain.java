package controls.domains;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import crypto.RSA;

public class Domain {

	protected String id;
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	protected String name;
	protected String configPath;
	public String getConfigPath() {
		return configPath;
	}	
	
	private PublicKey publicKey;
	private PrivateKey privateKey;
	
	public Domain(String id, String name) 
	{
		this.id = id;
		this.name = name;
		this.configPath = System.getenv("HOME") + "/." + id + "/";
	}
	
	public String toString()
	{
		return "{\"domain\": {\"id\": \"" + this.id + "\", \"name\": \"" + this.name + "\"}}";
	}
}