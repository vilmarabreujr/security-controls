package crypto;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class AES 
{
	public static String generateKey()
	{
		UUID uuid = UUID.randomUUID();
		String chave = uuid.toString(); //ABCAS-CDCD-ASDD-ASD
		chave = chave.replace("-", "");//ABCASCDCDASDDASD
		chave = chave.substring(0,16); 
		return chave;
	}
	public static byte[] cifra(String texto, String chave) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException
	{
		//Sobrecarga de método
		return cifra(texto.getBytes(), chave);
	}
	
	public static byte[] cifra(byte[] texto, String chave) 
			throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException
	{
		Key key = 
				new SecretKeySpec(chave.getBytes(StandardCharsets.UTF_8), "AES");
		Cipher cifrador = Cipher.getInstance("AES");
		cifrador.init(Cipher.ENCRYPT_MODE, key);
		byte[] textoCifrado = cifrador.doFinal(texto);
		return textoCifrado;
	}	
	
	public static String decifra(byte[] texto, String chave) 
			throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException
	{
	  	 Key key = new SecretKeySpec(chave.getBytes(StandardCharsets.UTF_8), "AES");
		 Cipher decifrador = Cipher.getInstance("AES");
		 decifrador.init(Cipher.DECRYPT_MODE, key);
    	 byte[] textoDecifrado = decifrador.doFinal(texto);
    	 return new String(textoDecifrado);
	}	
	
	public static String byteToString(byte[] textoCifrado)
	{
		return new String(textoCifrado);
	}
}
