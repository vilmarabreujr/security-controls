package controls.rbac;


public class ExportedRole extends Role{
	private String domain;
	public ExportedRole(String id, String domain) {
		super(id);
		this.domain = domain;
	}
	@Override
	public String toString()
	{
		return "{\"role\": {\"id\": \"" + this.id + "\", \"name\": \"" + this.name + "\", \"domain\": \"" + this.domain + "\"}}";
	}
}
