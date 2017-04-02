import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.xml.bind.DatatypeConverter;

public class ViewCert {
	public ViewCert() {
		// TODO Auto-generated constructor stub
	}

	public static void readcertificate(X509Certificate c)
			throws FileNotFoundException, CertificateException {

		System.out.println(c.toString());
	}

	public static PublicKey getpub_keys(X509Certificate c) {
		PublicKey pubkey = c.getPublicKey();
		System.out.println(pubkey.toString());
		return pubkey;
	}

	public static void getsignature(X509Certificate c) {
		byte[] sign = c.getSignature();
		BigInteger signature = new BigInteger(sign);
		System.out.println(String.format("%x", signature));
	}

	public static RSAPrivateKey getpriv_key(String raghu_pfx) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, NoSuchProviderException {
		FileInputStream fis = new FileInputStream(raghu_pfx);
		char[] password="raghu".toCharArray();
		KeyStore ks = KeyStore.getInstance("pkcs12", "SunJSSE");
		ks.load(fis, password);
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
		Enumeration<String> aliases = ks.aliases();
	
		KeyStore.PrivateKeyEntry priv_key_entry = (PrivateKeyEntry) ks.getEntry(aliases.nextElement(), protParam);
		RSAPrivateKey privkey = (RSAPrivateKey) priv_key_entry.getPrivateKey();
		System.out.println("Modulus:"+privkey.getModulus());
		System.out.println("Private Exponent:"+privkey.getPrivateExponent());
		return privkey;
	}
	public static byte[] encrypt(PublicKey pubkey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException, BadPaddingException{
		Cipher cip = Cipher.getInstance("RSA");
		String msg = "Our names are  Harshdeep and Namrata. We are enrolled in CSE 539.";
		cip.init(Cipher.ENCRYPT_MODE,pubkey);
		byte[] encrypted = cip.doFinal(msg.getBytes());
        String encryptedtext = new String(encrypted);
		System.out.println("Encrypted message is: " + encryptedtext);
		return encrypted;		
	}
	public static void decrypt(RSAPrivateKey privkey, byte[] encdata) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, IOException{
		Cipher decip = Cipher.getInstance("RSA");
		decip.init(Cipher.DECRYPT_MODE,privkey);
		byte[] decrypted = decip.doFinal(encdata);
		String orgmsg = new String(decrypted);
		System.out.println("Decrypted message is: " + orgmsg);
	}
	public static void main(String[] args) {
		try {
			System.out.println("Enter the path to Raghu's cretificate followed by Raghu's private key file and then the CA's certificate file. Please include the filename in the path.");
			
			
			InputStream raghu_crt = new FileInputStream(args[0]);
			String raghu_pfx = args[1];
			InputStream CA_crt = new FileInputStream(args[2]);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate c = (X509Certificate) cf.generateCertificate(raghu_crt);
			X509Certificate c2 = (X509Certificate) cf.generateCertificate(CA_crt);
			System.out.println("Printing Raghu's certificate");
			readcertificate(c);
			System.out.println("Printing Raghu's public key");
			PublicKey pubkey=getpub_keys(c);
			System.out.println("Printing Raghu's private key");
			RSAPrivateKey privkey=getpriv_key(raghu_pfx);
			System.out.println("Printing the signature");
			getsignature(c);
			System.out.println("Printing the public key of CA");
			PublicKey pubkey2=getpub_keys(c2);
			System.out.println("Encrypting");
			byte[] encdata = encrypt(pubkey);
			System.out.println("Decrypting");
			decrypt(privkey,encdata);
		} catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException | IOException | NoSuchProviderException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | ClassNotFoundException | BadPaddingException e) {
			// TODO Auto-generated catch block
			System.out.println(e);
		}
	}

}
