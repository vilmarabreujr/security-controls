package controls.rbac;

import java.util.ArrayList;
import java.util.List;

public class Session 
{
	private User user;
	private List<Role> listRoles;
	public Session(User user)
	{
		this.user = user;
		listRoles = new ArrayList<Role>();
	}
	public User getUser() {
		return user;
	}
	public void setUser(User user) {
		this.user = user;
	}
	public List<Role> getListRoles() {
		return listRoles;
	}
	public void setListRoles(List<Role> listRoles) {
		this.listRoles = listRoles;
	}
}
