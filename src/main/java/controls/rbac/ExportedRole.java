package controls.rbac;


public class ExportedRole extends Role{
	private String domain;
	private String originalRole;
	private String registeredRole;
	public String getDomain() {
		return domain;
	}
	public String getRegisteredRole() {
		return registeredRole;
	}
	public String getOriginalRole() {
		return originalRole;
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
