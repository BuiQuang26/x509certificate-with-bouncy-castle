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
