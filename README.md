# Certificate Path Generator Tool

A CLI utility compliant with WSO2 Registry standards. It extracts certificate issuer chains from **PEM** or **PKCS#12 (.p12)** files and generates the corresponding registry resource paths.

## Features

* **Support for Full Chains:** Extracts Root, Intermediate, and Leaf certificates.
* **Format Agnostic:** Handles `.pem`, `.crt`, `.p12`, and `.pfx` files.
* **WSO2 Normalization Logic:**
  1.  Extracts Issuer DN in RFC 2253 format.
  2.  Converts to lowercase.
  3.  Strips **all** spaces.
  4.  URL-encodes (UTF-8).
  5.  Replaces `%` with `:`.
* **Smart Deduplication:** Automatically removes duplicate entries (e.g., self-signed Root CAs appearing twice in a chain).

## Prerequisites

* **Java Development Kit (JDK):** Version 8, 11, 17, or 21+.
* **Maven:** Not required if using the included `mvnw` wrapper.

## Building the Project

Use the Maven Wrapper to build a standalone "Uber-JAR" (includes all dependencies):

```bash
# Linux / macOS
./mvnw clean package

# Windows
mvnw.cmd clean package
```

The executable JAR will be created at: `target/cert-path-tool-1.0.0.jar`

## Usage

### 1. Process a PEM Certificate Chain

Works with files containing one or more `-----BEGIN CERTIFICATE-----` blocks.

```bash
java -jar target/cert-path-tool-1.0.0.jar -f /path/to/certificate-chain.pem
```

### 2. Process a PKCS#12 Keystore

Extracts certificates from a `.p12` or `.pfx` file. You can provide the password via a flag or interactively.

**With password flag:**

```bash
java -jar target/cert-path-tool-1.0.0.jar -f /path/to/keystore.p12 -p changeit
```

**Interactive mode (secure):**

```bash
java -jar target/cert-path-tool-1.0.0.jar -f /path/to/keystore.p12
# You will be prompted to enter the password
```

### 3. Generate Path for Subject DN (Include Self)

Also generate a path for the certificate's own Subject DN. Use this when processing Intermediate/Root CA files.

```bash
java -jar target/cert-path-tool-1.0.0.jar -f /path/to/root-ca.pem -s
```

## Example Output

**Input Issuer DN:** `CN=Clients Intermediate CA, O=Demo CA, L=Londrina, ST=Parana, C=BR`

**Output Path:**

```text
/_system/governance/repository/security/certificate/certificate-authority/cn:3Dclientsintermediateca:2Co:3Ddemoca:2Cl:3Dlondrina:2Cst:3Dparana:2Cc:3Dbr
```

## Project Structure

```text
.
├── pom.xml                 # Maven configuration
├── mvnw / mvnw.cmd         # Maven Wrapper scripts
├── src
│   └── main
│       ├── java
│       │   └── org/wso2/support/sample/certpathgen
│       │       ├── CertPathTool.java       # Main CLI entry point
│       │       └── CertPathGenerator.java  # Core logic & formatting
│       └── resources
│           └── log4j2.xml                  # Logging configuration
└── target                  # Build output
```

## License
Copyright 2026. Licensed under the Apache License, Version 2.0.
