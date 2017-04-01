import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
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

public class ViewCert {
	public ViewCert() {
		// TODO Auto-generated constructor stub
	}

	public static void readcertificate(X509Certificate c)
			throws FileNotFoundException, CertificateException {

		System.out.println(c.toString());
	}

	public static void getpub_keys(X509Certificate c) {
		PublicKey pubkey = c.getPublicKey();
		System.out.println(pubkey.toString());

	}

	public static void getsignature(X509Certificate c) {
		System.out.println(c.getSignature());
	}

	public static void getpriv_key() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException, NoSuchProviderException {
		FileInputStream fis = new FileInputStream("/home/harsh/Documents/AppliedCrypto_HW5/certificate/Raghupri.pfx");
		char[] password="raghu".toCharArray();
		KeyStore ks = KeyStore.getInstance("pkcs12", "SunJSSE");
		ks.load(fis, password);
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
		Enumeration<String> aliases = ks.aliases();
	
		KeyStore.PrivateKeyEntry priv_key_entry = (PrivateKeyEntry) ks.getEntry(aliases.nextElement(), protParam);
		RSAPrivateKey privkey = (RSAPrivateKey) priv_key_entry.getPrivateKey();
		System.out.println("Modulus:"+privkey.getModulus());
		System.out.println("Private Exponent:"+privkey.getPrivateExponent());
	}

	public static void main(String[] args) {
		try {
			InputStream fis = new FileInputStream(
					"/home/harsh/Documents/AppliedCrypto_HW5/certificate/Raghupub.cer");
			InputStream fis2 = new FileInputStream(
					"/home/harsh/Documents/AppliedCrypto_HW5/certificate/Trustcenter.cer");
			// BufferedInputStream bis = new BufferedInputStream(fis);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate c = (X509Certificate) cf.generateCertificate(fis);
			X509Certificate c2 = (X509Certificate) cf.generateCertificate(fis2);
			System.out.println("Printing the certificate");
			readcertificate(c);
			System.out.println("Printing the public key");
			getpub_keys(c);
			System.out.println("Printing the private key");
			getpriv_key();
			System.out.println("Printing the signature");
			getsignature(c);
			System.out.println("Printing the public key of CA");
			getpub_keys(c2);
			
		} catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException | IOException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			System.out.println(e);
		}
	}

}
