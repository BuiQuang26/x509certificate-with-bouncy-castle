# X509certificate with Bouncy Castle

In this example, I will perform the creation of a child certificate signed by a self-signed root CA certificate using the Java library Bouncy Castle.

**This project is being used:**
- java 17
- build tool: maven

## Prepare self-signed root CA certificate using Openssl
- Generate root key
```shell
openssl genrsa -out ca-private.key 2048
```

- Generate root certificate
```shell
openssl req -x509 -new -nodes -key ca-private.key -sha256 -days 3650 -out ca-certificate.pem -days 36500
```

- Check the newly created root certificate
```shell
openssl x509 -in ca-certificate.pem -noout -text
```

- Create keystore from root-cert
```shell
openssl pkcs12 -export -in ca-certificate.pem -inkey ca-private.key -out keystore.p12 -name rootCa -passout pass:123456
```

## add dependency bouncy-castle
```xml
<!-- https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on -->
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
    <version>1.77</version>
</dependency>

<!-- https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk18on -->
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk18on</artifactId>
    <version>1.77</version>
</dependency>
```

## Load X509Certificate from a pem file

Load all certificates in the server-side CA certificate chain. "ca.pem" is the full file path of the server-side CA.

- Import package

```java
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
```

```java
Security.addProvider(new BouncyCastleProvider());
InputStream caInputStream = new FileInputStream("ca.pem");
CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
Collection<? extends Certificate> certs = certificateFactory.generateCertificates(caInput);

// Store the server-side CA certificates in the KeyStore.
KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
caKeyStore.load(null, null);
int index = 0;
for (Certificate cert : certs) {
    caKeyStore.setCertificateEntry("server_ca_" + index++, cert);
}
```

## Load Private RSA key from file key

- Import package

```java
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import javax.xml.bind.DatatypeConverter;
import java.security.PrivateKey;
```

```java
InputStream keyInputStream = new FileInputStream(properties.getMqtt().getTls().getKey());
BufferedReader reader = new BufferedReader(new InputStreamReader(keyInputStream));
StringBuilder stringBuilder = new StringBuilder();
String line;
String ls = System.lineSeparator();
while ((line = reader.readLine()) != null) {
    stringBuilder.append(line);
    stringBuilder.append(ls);
}
// delete the last new line separator
stringBuilder.deleteCharAt(stringBuilder.length() - 1);
reader.close();
String keyContent = stringBuilder.toString()
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(System.lineSeparator(), "");

PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(DatatypeConverter.parseBase64Binary(keyContent));
KeyFactory keyFactory = KeyFactory.getInstance("RSA");
PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
```
