package org.wso2.support.sample.certpathgen;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Set;
import java.util.TreeSet;
import javax.security.auth.x500.X500Principal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CertPathGenerator {

  private static final Logger logger = LogManager.getLogger(CertPathGenerator.class);
  private static final String BASE_PATH =
      "/_system/governance/repository/security/certificate/certificate-authority/";
  private static final String ENCODING_UTF8 = "UTF-8";

  public CertPathGenerator() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public Set<String> processPem(final File file, final boolean includeSelf) throws Exception {
    final Set<String> paths = new TreeSet<>();

    try (final InputStream is = new BufferedInputStream(Files.newInputStream(file.toPath()))) {
      final CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
      final Collection<? extends Certificate> certificates = factory.generateCertificates(is);

      for (final Certificate cert : certificates) {
        if (cert instanceof X509Certificate) {
          processSingleCert((X509Certificate) cert, paths, includeSelf);
        }
      }
    }
    return paths;
  }

  public Set<String> processP12(final File file, final char[] password, final boolean includeSelf)
      throws Exception {
    final Set<String> paths = new TreeSet<>();
    final KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");

    try (final InputStream is = new BufferedInputStream(Files.newInputStream(file.toPath()))) {
      keystore.load(is, password);
    }

    final Enumeration<String> aliases = keystore.aliases();
    while (aliases.hasMoreElements()) {
      final String alias = aliases.nextElement();
      final Certificate[] chain = keystore.getCertificateChain(alias);

      if (chain != null) {
        for (final Certificate cert : chain) {
          if (cert instanceof X509Certificate) {
            processSingleCert((X509Certificate) cert, paths, includeSelf);
          }
        }
      } else {
        final Certificate cert = keystore.getCertificate(alias);
        if (cert instanceof X509Certificate) {
          processSingleCert((X509Certificate) cert, paths, includeSelf);
        }
      }
    }
    return paths;
  }

  private void processSingleCert(
      final X509Certificate cert, final Set<String> paths, boolean includeSelf) {
    try {
      paths.add(generatePath(cert.getIssuerX500Principal()));

      if (includeSelf) {
        paths.add(generatePath(cert.getSubjectX500Principal()));
      }
    } catch (final UnsupportedEncodingException e) {
      logger.error("Encoding error for cert: {}", cert.getSubjectX500Principal().getName(), e);
    }
  }

  String generatePath(final X500Principal principal) throws UnsupportedEncodingException {
    final String dn = principal.getName(X500Principal.RFC2253);
    final String normalized = dn.toLowerCase().replace(" ", "");
    final String encoded = URLEncoder.encode(normalized, ENCODING_UTF8);
    return BASE_PATH + encoded.replaceAll("%", ":");
  }
}
