package crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSA {

	  public static final String ALGORITHM = "RSA";
	  private static String PROPS_FILE = "/.keyRepository/";

	  public static void generateKey(String PRIVATE_KEY_FILE, String PUBLIC_KEY_FILE) {
		    try {
		    		boolean exists = false;
			        String homeDir = System.getenv("HOME") + PROPS_FILE;
			        PRIVATE_KEY_FILE = homeDir + PRIVATE_KEY_FILE;
			        PUBLIC_KEY_FILE = homeDir + PUBLIC_KEY_FILE;
		    		File privateKeyFile = new File(PRIVATE_KEY_FILE);
		    		File publicKeyFile = new File(PUBLIC_KEY_FILE);
		    		if(privateKeyFile.exists() && publicKeyFile.exists()) { 
		    			exists = true;
		    		}
		    		
		    		if( !exists )
		    		{
		    			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
		    			keyGen.initialize(4096);
		    			KeyPair key = keyGen.generateKeyPair();					        
					
		    			// Create files to store public and private key
		    			if (privateKeyFile.getParentFile() != null) {
		    				privateKeyFile.getParentFile().mkdirs();
		    			}
		    			privateKeyFile.createNewFile();
					
		    			if (publicKeyFile.getParentFile() != null) {
		    				publicKeyFile.getParentFile().mkdirs();
		    			}
		    			publicKeyFile.createNewFile();
					
		    			// Saving the Public key in a file
		    			ObjectOutputStream publicKeyOS = new ObjectOutputStream(
					      new FileOutputStream(publicKeyFile));
		    			publicKeyOS.writeObject(key.getPublic());
		    			publicKeyOS.close();
					
		    			// Saving the Private key in a file
		    			ObjectOutputStream privateKeyOS = new ObjectOutputStream(
					      new FileOutputStream(privateKeyFile));
		    			privateKeyOS.writeObject(key.getPrivate());
		    			privateKeyOS.close();
		    		}
		    } catch (Exception e) {
		    	  e.printStackTrace();
		    }	
	  }

	  public static String encrypt(String text, Key key) {
		    byte[] cipherText = null;
		    try {
			    // get an RSA cipher object and print the provider
			    Cipher cipher = Cipher.getInstance(ALGORITHM);
			    // encrypt the plain text using the key
			    cipher.init(Cipher.ENCRYPT_MODE, key);
			    cipherText = cipher.doFinal(text.getBytes());
		    } catch (Exception e) {
		    	e.printStackTrace();
		    }
		    
		    return Base64.getEncoder().encodeToString(cipherText);
	  }

	  public static String decrypt(String text, Key key) {
		  	byte[] cipherText = Base64.getDecoder().decode(text);
			byte[] dectyptedText = null;
			try {
				// get an RSA cipher object and print the provider
				Cipher cipher = Cipher.getInstance(ALGORITHM);
				
				// decrypt the text using the key
				cipher.init(Cipher.DECRYPT_MODE, key);
				dectyptedText = cipher.doFinal(cipherText);
			
			} catch (Exception ex) {
				ex.printStackTrace();
			}
			
			return new String(dectyptedText);
	  }
	  
	  public static PrivateKey loadPrivateKey(String path) throws FileNotFoundException, IOException, ClassNotFoundException
	  {
	      String homeDir = System.getenv("HOME") + PROPS_FILE;
		  ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(homeDir + path));
	      PrivateKey privateKey = (PrivateKey) inputStream.readObject();
	      return privateKey;		  
	  }
	  
	  public static PublicKey loadPublicKey(String path) throws FileNotFoundException, IOException, ClassNotFoundException
	  {
	      String homeDir = System.getenv("HOME") + PROPS_FILE;
		  ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(homeDir + path));
		  PublicKey publicKey = (PublicKey) inputStream.readObject();
	      return publicKey;		  
	  }
	  
}
