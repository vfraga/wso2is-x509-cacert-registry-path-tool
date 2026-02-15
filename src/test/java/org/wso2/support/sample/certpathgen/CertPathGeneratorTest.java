package org.wso2.support.sample.certpathgen;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CertPathGeneratorTest {

  @TempDir File tempDir;

  private static final String PROVIDER = "BC";
  private static final String SIG_ALGO = "SHA256WithRSA";
  private static final char[] P12_PASSWORD = "testpass".toCharArray();
  private static final String EXPECTED_BASE =
      "/_system/governance/repository/security/certificate/certificate-authority/";

  @BeforeAll
  static void setup() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  @DisplayName("Should correctly parse a PEM file containing a full certificate chain")
  void testProcessPemChain() throws Exception {
    final KeyPair rootPair = generateKeyPair();
    final X509Certificate rootCert =
        generateCert(
            "CN=Root, O=Test, C=US", rootPair, "CN=Root, O=Test, C=US", rootPair.getPublic());

    final KeyPair interPair = generateKeyPair();
    final X509Certificate interCert =
        generateCert(
            "CN=Inter, O=Test, C=US", rootPair, "CN=Root, O=Test, C=US", interPair.getPublic());

    final KeyPair leafPair = generateKeyPair();
    final X509Certificate leafCert =
        generateCert(
            "CN=Leaf, O=Test, C=US", interPair, "CN=Inter, O=Test, C=US", leafPair.getPublic());

    final File pemFile = new File(tempDir, "chain.pem");
    try (final JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(pemFile))) {
      writer.writeObject(leafCert);
      writer.writeObject(interCert);
      writer.writeObject(rootCert);
    }

    final CertPathGenerator generator = new CertPathGenerator();
    final Set<String> result = generator.processPem(pemFile, false);

    // Expecting 2 unique Issuer paths: Issuer of Leaf (Inter) and Issuer of Inter (Root)
    assertEquals(2, result.size());
    assertTrue(result.contains(EXPECTED_BASE + "c:3Dus:2Co:3Dtest:2Ccn:3Droot"));
    assertTrue(result.contains(EXPECTED_BASE + "c:3Dus:2Co:3Dtest:2Ccn:3Dinter"));
  }

  @Test
  @DisplayName("Should include Subject path when includeSelf is true (Partial Chain Scenario)")
  void testPartialChainWithSelfFlag() throws Exception {
    // Scenario: File contains ONLY Intermediate and Root (No end entity user)
    final KeyPair rootPair = generateKeyPair();
    final X509Certificate rootCert =
        generateCert(
            "CN=Root, O=Test, C=US", rootPair, "CN=Root, O=Test, C=US", rootPair.getPublic());

    final KeyPair interPair = generateKeyPair();
    final X509Certificate interCert =
        generateCert(
            "CN=Inter, O=Test, C=US", rootPair, "CN=Root, O=Test, C=US", interPair.getPublic());

    final File pemFile = new File(tempDir, "partial.pem");
    try (final JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(pemFile))) {
      writer.writeObject(interCert);
      writer.writeObject(rootCert);
    }

    final CertPathGenerator generator = new CertPathGenerator();
    // Enable -s / --include-self
    final Set<String> result = generator.processPem(pemFile, true);

    // Expectation:
    // 1. Root Cert: Issuer=Root, Subject=Root -> generates Path(Root)
    // 2. Inter Cert: Issuer=Root -> generates Path(Root) [Duplicate, ignored]
    // 3. Inter Cert: Subject=Inter -> generates Path(Inter)

    // Total should be 2 unique paths: Root and Inter
    assertEquals(2, result.size());

    final String rootPath = EXPECTED_BASE + "c:3Dus:2Co:3Dtest:2Ccn:3Droot";
    final String interPath = EXPECTED_BASE + "c:3Dus:2Co:3Dtest:2Ccn:3Dinter";

    assertTrue(result.contains(rootPath), "Should contain Root path");
    assertTrue(result.contains(interPath), "Should contain Intermediate path (Self/Subject)");
  }

  @Test
  @DisplayName("Should correctly parse a PKCS#12 file with a chain")
  void testProcessP12Chain() throws Exception {
    final KeyPair rootPair = generateKeyPair();
    final X509Certificate rootCert =
        generateCert("CN=P12 Root, O=Test", rootPair, "CN=P12 Root, O=Test", rootPair.getPublic());

    final KeyPair leafPair = generateKeyPair();
    final X509Certificate leafCert =
        generateCert("CN=P12 Leaf, O=Test", rootPair, "CN=P12 Root, O=Test", leafPair.getPublic());

    final KeyStore store = KeyStore.getInstance("PKCS12", PROVIDER);
    store.load(null, null);
    store.setKeyEntry(
        "myalias", leafPair.getPrivate(), P12_PASSWORD, new Certificate[] {leafCert, rootCert});

    final File p12File = new File(tempDir, "test.p12");
    try (final FileOutputStream fos = new FileOutputStream(p12File)) {
      store.store(fos, P12_PASSWORD);
    }

    final CertPathGenerator generator = new CertPathGenerator();
    final Set<String> result = generator.processP12(p12File, P12_PASSWORD, false);

    assertEquals(1, result.size());
    assertTrue(result.contains(EXPECTED_BASE + "o:3Dtest:2Ccn:3Dp12root"));
  }

  @Test
  @DisplayName("Should handle specific logic (Case insensitive, space stripping) correctly")
  void testNormalizationLogic() throws Exception {
    final KeyPair pair = generateKeyPair();
    final X509Certificate cert =
        generateCert("CN=Leaf", pair, "CN=My  Mixed  CASE  CA, O=Org", pair.getPublic());

    final CertPathGenerator generator = new CertPathGenerator();
    final String result = generator.generatePath(cert.getIssuerX500Principal());

    final String expected = EXPECTED_BASE + "o:3Dorg:2Ccn:3Dmymixedcaseca";
    assertEquals(expected, result);
  }

  private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
    final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048, new SecureRandom());
    return generator.generateKeyPair();
  }

  private X509Certificate generateCert(
      String subjectDn, KeyPair issuerKeys, String issuerDn, java.security.PublicKey publicKey)
      throws Exception {
    final long now = System.currentTimeMillis();
    final X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            new X500Name(issuerDn),
            BigInteger.valueOf(now),
            new Date(now),
            new Date(now + 1000 * 60 * 60),
            new X500Name(subjectDn),
            publicKey);

    final ContentSigner signer =
        new JcaContentSignerBuilder(SIG_ALGO).setProvider(PROVIDER).build(issuerKeys.getPrivate());
    return new JcaX509CertificateConverter()
        .setProvider(PROVIDER)
        .getCertificate(builder.build(signer));
  }
}
