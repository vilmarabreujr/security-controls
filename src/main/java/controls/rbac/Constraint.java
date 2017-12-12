package controls.rbac;

public class Constraint {
	private Role roleA;
	private Role roleB;
	public Constraint(Role roleA, Role roleB)
	{
		this.roleA = roleA;
		this.roleB = roleB;
	}
	
	public boolean Exist(Role roleA, Role roleB)
	{
		if( this.roleA == roleA || this.roleA == roleB )
		{
			if( this.roleB == roleA || this.roleB == roleB )
			{
				return true;
			}
		}
		return false;
	}
	
	public String toString()
	{
		return "{\"constraint\": {\"roleA\": \"" + this.roleA.getId() + "\", \"roleB\": \"" + this.roleB.getId() + "\"}}";
	}
}
