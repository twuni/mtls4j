package dev.twuni.mtls4j;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Parse PEM-encoded X.509 certificates and private keys.
 */
public class PEM {
  private static final String EC = "EC";
  private static final String RSA = "RSA";
  private static final String X509 = "X.509";
  private static final String UTF8 = "UTF-8";
  private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
  private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
  private static final String EMPTY = "";

  /**
   * Parse a given PEM-encoded X.509 certificate as a {@link Certificate} object.
   *
   * @param input a PEM-encoded X.509 certificate
   *
   * @return the parsed certificate
   *
   * @throws CertificateException if the given input string cannot be parsed
   */
  public static Certificate parseCertificate(final String input) throws CertificateException {
    return parseCertificate(input.getBytes(Charset.forName(UTF8)));
  }

  /**
   * Parse a given PEM-encoded X.509 certificate as a {@link Certificate} object.
   *
   * @param input a PEM-encoded X.509 certificate
   *
   * @return the parsed certificate
   *
   * @throws CertificateException if the given input string cannot be parsed
   */
  public static Certificate parseCertificate(final byte[] input) throws CertificateException {
    return parseCertificate(new ByteArrayInputStream(input));
  }

  /**
   * Parse a given PEM-encoded X.509 certificate as a {@link Certificate} object.
   *
   * @param input a PEM-encoded X.509 certificate
   *
   * @return the parsed certificate
   *
   * @throws CertificateException if the given input string cannot be parsed
   */
  public static Certificate parseCertificate(final InputStream input) throws CertificateException {
    return CertificateFactory.getInstance(X509).generateCertificate(input);
  }

  /**
   * Parse a given PEM-encoded PKCS#8 private key as a {@link PrivateKey} object.
   *
   * @param input a PEM-encoded PKCS#8 private key (must not be encrypted)
   *
   * @return the parsed EC private key
   *
   * @throws InvalidKeySpecException if the given input string cannot be parsed as an EC private key
   * @throws NoSuchAlgorithmException if the EC key algorithm is not supported on this system
   */
  public static PrivateKey parseECPrivateKey(final String input) throws InvalidKeySpecException, NoSuchAlgorithmException {
    return parsePrivateKey(input, EC);
  }

  /**
   * Parse a given PEM-encoded PKCS#8 private key as a {@link PrivateKey} object.
   * This is a convenience method to try parsing the input string as an RSA private
   * key, and if anything goes wrong while attempting to do so, to try parsing it
   * as an EC private key instead. If you know the type of private key in advance,
   * then you may want to use {@link #parseECPrivateKey(String)} or
   * {@link #parseRSAPrivateKey(String)} instead.
   *
   * @param input a PEM-encoded PKCS#8 private key (must not be encrypted)
   *
   * @return the parsed private key
   *
   * @throws InvalidKeySpecException if the given input string cannot be parsed as a private key using any of the currently supported default algorithms
   * @throws NoSuchAlgorithmException none of the default key algorithms known to this object are supported on this system
   */
  public static PrivateKey parsePrivateKey(final String input) throws InvalidKeySpecException, NoSuchAlgorithmException {
    try {
      return parseRSAPrivateKey(input);
    } catch (Throwable tryAnotherAlgorithm) {
      return parseECPrivateKey(input);
    }
  }

  /**
   * Parse a given PEM-encoded PKCS#8 private key as a {@link PrivateKey} object.
   *
   * @param input a PEM-encoded PKCS#8 private key (must not be encrypted)
   * @param algorithm the algorithm to use when attempting to parse the key (e.g: "RSA", "EC")
   *
   * @return the parsed private key
   *
   * @throws InvalidKeySpecException if the given input string cannot be parsed as a private key using the given <code>algorithm</code>
   * @throws NoSuchAlgorithmException if the given algorithm is not supported on this system
   */
  public static PrivateKey parsePrivateKey(final String input, final String algorithm) throws InvalidKeySpecException, NoSuchAlgorithmException {
    KeyFactory factory = KeyFactory.getInstance(algorithm);
    byte[] encodedPrivateKey = Base64.getDecoder().decode(input.replace(BEGIN_PRIVATE_KEY, EMPTY).replaceAll(System.lineSeparator(), EMPTY).replace(END_PRIVATE_KEY, EMPTY));
    KeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
    return factory.generatePrivate(keySpec);
  }

  /**
   * Parse a given PEM-encoded PKCS#8 private key as a {@link PrivateKey} object.
   *
   * @param input a PEM-encoded PKCS#8 private key (must not be encrypted)
   *
   * @return the parsed RSA private key
   *
   * @throws InvalidKeySpecException if the given input string cannot be parsed as an RSA private key
   * @throws NoSuchAlgorithmException if the RSA key algorithm is not supported on this system
   */
  public static PrivateKey parseRSAPrivateKey(final String input) throws InvalidKeySpecException, NoSuchAlgorithmException {
    return parsePrivateKey(input, RSA);
  }

  private PEM() {
    // This is just a utility class.
  }
}
