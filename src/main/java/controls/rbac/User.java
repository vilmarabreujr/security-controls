package controls.rbac;

import java.util.ArrayList;
import java.util.List;

public class User 
{
	private String id;
	private String name;
	private List<Role> listRoles;
	public User(String id)
	{
		this.id = id;
		this.name = id;
		this.listRoles = new ArrayList<Role>();
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
