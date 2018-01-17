package controls.domains;

import java.util.ArrayList;
import java.util.List;

public class DomainController 
{
	private static DomainController inst;
	private List<Domain> domains;
	private DomainController()
	{
		domains = new ArrayList<Domain>();
		init();
	}
	public static DomainController getInstance()
	{
		if( inst == null )
		{
			inst = new DomainController();
		}
		return inst;
	}
	public List<Domain> getDomains()
	{
		return domains;
	}	
	public void init()
	{
		Domain d1 = new Domain("pucpr", "PUCPR");
		Domain d2 = new Domain("ufpr", "UFPR");
		Domain d3 = new Domain("utfpr", "UTFPR");
		domains.add(d1);
		domains.add(d2);
		domains.add(d3);
	}
	public boolean isTrustDomain(String domain)
	{
		for( Domain d : domains )
		{
			if( d.getId().equals(domain) )
				return true;
		}
		return false;
	}
	public Domain getDomain(String domain)
	{
		for( Domain d : domains )
		{
			if( d.getId().equals(domain) )
				return d;
		}
		return null;
	}
}
