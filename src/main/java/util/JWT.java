package util;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;

import com.google.gdata.util.common.util.Base64;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

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
}
