package vn.buiquang26.x509certificateWithBouncyCastle;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class X509certificateWithBouncyCastleApplication {

	private static final String BC_PROVIDER = "BC";

	private static final String KEY_ALGORITHM = "RSA";

	private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

	private static final String KEY_STORE_PATH = "keystore.p12";

	private static final String KEY_STORE_CA_PASS = "123456";

	private static final String KEY_STORE_TYPE = "PKCS12";

	private static final String KEY_STORE_CA_NAME = "rootCa";

	public static void main(String[] args) throws Exception {
		// Add the BouncyCastle Provider
		Security.addProvider(new BouncyCastleProvider());

		// load root certificate
		KeyStoreDTO caKeyStoreDTO = loadRootCaKeyStore();

		// create keypair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// Setup start date to yesterday and end date for 10 year validity
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.DATE, -1);
		Date startDate = calendar.getTime();
		calendar.add(Calendar.YEAR, 10);
		Date endDate = calendar.getTime();

		// create x509certificate signed by root ca
		X509Certificate myCertificate = generateX509CertificateSignedByRootCert("myCertificate", keyPair, caKeyStoreDTO.getPrivateKey(), caKeyStoreDTO.getCertificate(), startDate, endDate);

		// show private key
		System.out.println(privateKeyToBase64Pem(keyPair.getPrivate()));
		System.out.println();
		// show certificate chain signed by root cert
		System.out.println(x509CertificateToBase64Pem(myCertificate));

	}

	/**
	 * tạo chứng chỉ x509 cho client và ký bằng root CA
	 * */
	public static X509Certificate generateX509CertificateSignedByRootCert(String commonName, KeyPair keyPair, PrivateKey caPrivateKey, X509Certificate caCertificate, Date startDate, Date enddate)
			throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException {
		X500Name rootCertIssuer = new JcaX509CertificateHolder(caCertificate).getSubject();
		X500Name issuedCertSubject = new X500Name("CN=" + commonName);
		BigInteger clientCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

		// create certificate request builder
		PKCS10CertificationRequestBuilder certificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, keyPair.getPublic());

		// Sign the new KeyPair with the root Private Key
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
		ContentSigner contentSigner = signerBuilder.build(caPrivateKey);

		var csr = certificationRequestBuilder.build(contentSigner);

		// Use the Signed KeyPair and CSR to generate an issued Certificate
		// Here serial number is randomly generated. In general, CAs use
		// a sequence to generate Serial number and avoid collisions
		X509v3CertificateBuilder clientCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, clientCertSerialNum, startDate, enddate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

		// Add Extensions
		// Use BasicConstraints to say that this Cert is not a CA
		JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();
		clientCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
		// Add Issuer cert identifier as Extension
		clientCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(caCertificate));
		clientCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

		X509CertificateHolder clientCertHolder = clientCertBuilder.build(contentSigner);
		return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(clientCertHolder);
	}

	public static KeyStoreDTO loadRootCaKeyStore() throws KeyStoreException, NoSuchProviderException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
		KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE, BC_PROVIDER);
		InputStream inputStream = new FileInputStream(KEY_STORE_PATH);
		keyStore.load(inputStream, KEY_STORE_CA_PASS.toCharArray());
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_STORE_CA_NAME, null);
		X509Certificate certificate = (X509Certificate) keyStore.getCertificate(KEY_STORE_CA_NAME);
		KeyStoreDTO keyStoreDTO = new KeyStoreDTO();
		keyStoreDTO.setPrivateKey(privateKey);
		keyStoreDTO.setCertificate(certificate);
		return keyStoreDTO;
	}

	public static class KeyStoreDTO {
		private PrivateKey privateKey;
		private X509Certificate certificate;

		public PrivateKey getPrivateKey() {
			return privateKey;
		}

		public void setPrivateKey(PrivateKey privateKey) {
			this.privateKey = privateKey;
		}

		public X509Certificate getCertificate() {
			return certificate;
		}

		public void setCertificate(X509Certificate certificate) {
			this.certificate = certificate;
		}
	}

	public static String privateKeyToBase64Pem(PrivateKey privateKey) {
		return "-----BEGIN PRIVATE KEY-----" + System.lineSeparator() +
				bytesToBase64(Base64.encode(privateKey.getEncoded())) +
				"-----END PRIVATE KEY-----";
	}

	public static String x509CertificateToBase64Pem(Certificate certificate) throws CertificateEncodingException {
		return "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
				bytesToBase64(Base64.encode(certificate.getEncoded())) +
				"-----END CERTIFICATE-----";
	}

	public static String bytesToBase64(byte[] base64Cert) {
		StringBuilder builder = new StringBuilder();
		char[] charArray = new String(base64Cert, StandardCharsets.UTF_8).toCharArray();
		int i = 0;
		int index = 0;
		while (index < charArray.length) {
			builder.append(charArray[index]);
			i++;
			index++;
			if (i == 63 || index == charArray.length) {
				builder.append(System.getProperty("line.separator"));
				i = 0;
			}
		}
		return builder.toString();
	}
}
