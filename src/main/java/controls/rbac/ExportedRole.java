package controls.rbac;


public class ExportedRole extends Role{
	private String domain;
	private String originalRole;
	private String registeredRole;
	public String getDomain() {
		return domain;
	}
	public ExportedRole(String id, String originalRole, String registeredRole, String domain) {
		super(id);
		this.domain = domain;
		this.originalRole = originalRole;
		this.registeredRole = registeredRole;
	}
	@Override
	public String toString()
	{
		return "{\"role\": {\"id\": \"" + this.id + "\", \"name\": \"" + this.name + "\", \"domain\": \"" + this.domain + "\"}}";
	}
}
