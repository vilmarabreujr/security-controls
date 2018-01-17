package controls.domains;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import util.RSA;

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
	public PublicKey getPublicKey() {
		return publicKey;
	}
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	protected String name;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	
	public Domain(String id, String name) 
	{
		this.id = id;
		this.name = name;

    	String PRIVATE_KEY_FILE = id + "_private.key";
    	String PUBLIC_KEY_FILE =  id + "_public.key";		
		try 
		{
			RSA.generateKey(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE);
			this.publicKey = RSA.loadPublicKey(PUBLIC_KEY_FILE);
			this.privateKey = RSA.loadPrivateKey(PRIVATE_KEY_FILE);
		
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public String toString()
	{
		return "{\"domain\": {\"id\": \"" + this.id + "\", \"name\": \"" + this.name + "\"}}";
	}
}