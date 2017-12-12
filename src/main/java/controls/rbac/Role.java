package controls.rbac;

import java.util.ArrayList;
import java.util.List;

public class Role 
{
	private String id;
	private String name;
	private List<User> listUsers;
	public Role(String id)
	{
		this.id = id;
		this.name = id;
		this.listUsers = new ArrayList<User>();
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
	public void addUser(User user)
	{
		this.listUsers.add(user);
	}
	public String toString()
	{
		return "{\"role\": {\"id\": \"" + this.id + "\", \"name\": \"" + this.name + "\"}}";
	}
}
