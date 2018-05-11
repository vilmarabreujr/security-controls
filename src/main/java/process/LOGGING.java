package process;

public class LOGGING 
{
	private static boolean DEBBUG_MODE = false;
	public static void print(String msg)
	{
		if( DEBBUG_MODE )
			System.out.println(msg);
	}
	
	public static void printAlways(String msg)
	{
		System.out.println(msg);
	}
}
