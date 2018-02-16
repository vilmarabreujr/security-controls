package controls.rbac;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import crypto.RSA;

public class User 
{
	private String id;
	private String name;
	private List<Role> listRoles;

	private PublicKey publicKey;
	private PrivateKey privateKey;

	public PublicKey getPublicKey() {
		return publicKey;
	}
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	
	public User(String id)
	{
		this.id = id;
		this.name = id;
		this.listRoles = new ArrayList<Role>();
		
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
	public void addRole(Role role)
	{
		this.listRoles.add(role);
	}
	public List<Role> getRoles()
	{
		return this.listRoles;
	}
}
