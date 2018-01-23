package util;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;

public class JWT 
{
	private static String certificatePath = "/home/aluno/Documentos/wso2is-5.3.0/repository/resources/security/wso2carbon.jks";
	public static boolean ValidateToken(String tokenString)
	{
		try
		{
			RSAPublicKey publicKey = null;
	        InputStream file = new FileInputStream(certificatePath);
	        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	        keystore.load(file, "wso2carbon".toCharArray());
	 
	        String alias = "wso2carbon";
	 
	        // Get certificate of public key
	        Certificate cert = keystore.getCertificate(alias);
	        // Get public key
	        publicKey = (RSAPublicKey) cert.getPublicKey();
	 
	        SignedJWT signedJWT = SignedJWT.parse(tokenString);
	 
	        JWSVerifier verifier = new RSASSAVerifier(publicKey);
	 
	        if (signedJWT.verify(verifier)) {
	            System.out.println("Signature is Valid");
	            return true;
	        } else {
	            System.out.println("Signature is NOT Valid");
	            return false;
	        }
		}
		catch(Exception e)
		{
            System.out.println("Error: " + e.getMessage());
            return false;
		}		
	}
	
	public static void processToken(String tokenString)
	{
		try
		{
			String[] list = tokenString.split("\\.");
			byte[] header = Base64.decodeBase64(list[0]);
			System.out.println("\t" + new String(header, "UTF-8"));

			byte[] body = Base64.decodeBase64(list[1]);
			System.out.println("\t" + new String(body, "UTF-8"));			

			//ValidateToken(tokenString);					
		}
		catch(Exception e)
		{
			System.out.println(e.getMessage());
		}		
	}
	
	
}
