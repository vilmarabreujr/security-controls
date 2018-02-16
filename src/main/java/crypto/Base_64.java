package crypto;

import java.util.Base64;

public class Base_64 {
	public static String encode(byte[] array)
	{
	    return Base64.getEncoder().encodeToString(array);
	}
	
	public static byte[] decode(String text)
	{
	  	return Base64.getDecoder().decode(text);
	}
	
	public static String decodeString(String text)
	{
	  	return new String(decode(text));
	}
}
