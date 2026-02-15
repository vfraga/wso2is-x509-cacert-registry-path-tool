package org.wso2.support.sample.certpathgen;

import java.io.Console;
import java.io.File;
import java.util.Set;
import java.util.concurrent.Callable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
    name = "cert-path-tool",
    mixinStandardHelpOptions = true,
    version = "1.0",
    description = "Generates repository paths from certificate issuer DNs (PEM or P12).")
public class CertPathTool implements Callable<Integer> {

  private static final Logger logger = LogManager.getLogger(CertPathTool.class);

  @SuppressWarnings("unused")
  @Option(
      names = {"-f", "--file"},
      required = true,
      description = "Path to the certificate file (.pem, .crt, .p12, .pfx).")
  private File certFile = null;

  @SuppressWarnings("unused")
  @Option(
      names = {"-p", "--password"},
      description =
          "Password for the PKCS#12 keystore. If omitted for a locked file, you will be prompted interactively.")
  private char[] password = null;

  @SuppressWarnings("unused")
  @Option(
      names = {"-s", "--include-self"},
      description =
          "Also generate a path for the certificate's own Subject DN. Use this when processing Intermediate/Root CA files.")
  private boolean includeSelf = false;

  public static void main(final String[] args) {
    final int exitCode = new CommandLine(new CertPathTool()).execute(args);
    System.exit(exitCode);
  }

  @Override
  public Integer call() {
    if (certFile == null || !certFile.exists()) {
      logger.error("File not found: {}", (certFile != null ? certFile.getAbsolutePath() : "null"));
      return 1;
    }

    try {
      final CertPathGenerator generator = new CertPathGenerator();
      final Set<String> paths;
      final String fileName = certFile.getName().toLowerCase();

      if (fileName.endsWith(".p12") || fileName.endsWith(".pfx")) {
        logger.info("Processing PKCS#12 keystore: {}", certFile.getName());
        paths = handleP12Logic(generator);
      } else {
        logger.info("Processing PEM/CRT file: {}", certFile.getName());
        paths = generator.processPem(certFile, includeSelf);
      }

      if (paths.isEmpty()) {
        logger.warn("No certificates found or processed.");
      } else {
        System.out.println("--- Generated Paths ---");
        for (final String path : paths) {
          System.out.println(path);
        }
      }
      return 0;

    } catch (final Exception e) {
      if (e.getMessage() != null && e.getMessage().contains("password")) {
        logger.error("Keystore error: {}", e.getMessage());
        logger.info("Tip: If running non-interactively, use -p <password>.");
      } else {
        logger.error("Error processing certificates: {}", e.getMessage(), e);
      }
      return 2;
    }
  }

  private Set<String> handleP12Logic(final CertPathGenerator generator) throws Exception {
    if (password != null) {
      return generator.processP12(certFile, password, includeSelf);
    }

    try {
      logger.debug("Attempting to open keystore without password...");
      return generator.processP12(certFile, null, includeSelf);
    } catch (final Exception e) {
      final Console console = System.console();
      if (console != null) {
        logger.info("Keystore seems to be locked.");
        final char[] interactivePass = console.readPassword("Enter keystore password: ");
        return generator.processP12(certFile, interactivePass, includeSelf);
      } else {
        throw e;
      }
    }
  }
}
