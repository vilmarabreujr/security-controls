package crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
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
		    
		    return Base_64.encode(cipherText);
	  }

	  public static String decrypt(String text, Key key) {
		  	byte[] cipherText = Base_64.decode(text);
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
	  
	  
	  public static PrivateKey stringToPrivateKey(String key64) throws GeneralSecurityException {
		    byte[] clear = Base_64.decode(key64);
		    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
		    KeyFactory fact = KeyFactory.getInstance(ALGORITHM);
		    PrivateKey priv = fact.generatePrivate(keySpec);
		    Arrays.fill(clear, (byte) 0);
		    return priv;
		}


		public static PublicKey stringToPublicKey(String stored) throws GeneralSecurityException {
		    byte[] data = Base_64.decode(stored);
		    X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
		    KeyFactory fact = KeyFactory.getInstance(ALGORITHM);
		    return fact.generatePublic(spec);
		}

		public static String privateKeyToString(PrivateKey priv) throws GeneralSecurityException {
		    KeyFactory fact = KeyFactory.getInstance(ALGORITHM);
		    PKCS8EncodedKeySpec spec = fact.getKeySpec(priv,
		            PKCS8EncodedKeySpec.class);
		    byte[] packed = spec.getEncoded();
		    String key64 = Base_64.encode(packed);

		    Arrays.fill(packed, (byte) 0);
		    return key64;
		}


		public static String publicKeyToString(PublicKey publ) throws GeneralSecurityException {
		    KeyFactory fact = KeyFactory.getInstance(ALGORITHM);
		    X509EncodedKeySpec spec = fact.getKeySpec(publ,
		            X509EncodedKeySpec.class);
		    return Base_64.encode(spec.getEncoded());
		}
	  
}
