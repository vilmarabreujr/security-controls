package controls.domains;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

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
		Domain d1 = new Domain("copel", "COPEL");
		Domain d2 = new Domain("furnas", "FURNAS");
		Domain d3 = new Domain("eletrobras", "ELETROBRAS");
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

	public Domain getDomain(HttpServletRequest httpRequest)
	{
		String uri = httpRequest.getRequestURI();
		String context = httpRequest.getContextPath();
		uri = uri.replaceAll(context, "");
		String domain = uri.split("/")[1];
		for( Domain d : domains )
		{
			if( d.getId().equals(domain) )
				return d;
		}
		return null;
	}
	
}
