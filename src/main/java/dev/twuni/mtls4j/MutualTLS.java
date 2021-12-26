package dev.twuni.mtls4j;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.DrbgParameters;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Need an {@link SSLContext} configured for mTLS? Start here!
 */
public class MutualTLS {
  private static final String TLS_1_3 = "TLSv1.3";
  private static final String ALIAS_CLIENT = "client";
  private static final String ALIAS_SERVER = "server";
  private static final String DEFAULT_PASSPHRASE = "nevergonnagiveyouup";
  private static final String DRBG = "DRBG";
  private static final String UTF8 = "UTF-8";

  private final Certificate[] clientCertificateChain;
  private final PrivateKey clientKey;
  private final char[] keyStorePassphrase;
  private final Certificate[] trustedCertificates;

  /**
   * Prepares an mTLS context with the given configuration.
   *
   * @param clientCertificateChain the client certificate followed by any intermediate certificates that may be needed for the peer to trace the signature chain to one of its trust anchors
   * @param clientKey the private key paired with the client certificate
   * @param trustedCertificates one or more certificates to mark as trusted -- any certificates presented by peers must have a signature chain traceable to at least one of these certificates
   */
  public MutualTLS(final Certificate[] clientCertificateChain, final PrivateKey clientKey, final Certificate[] trustedCertificates) {
    this(clientCertificateChain, clientKey, DEFAULT_PASSPHRASE.toCharArray(), trustedCertificates);
  }

  private MutualTLS(final Certificate[] clientCertificateChain, final PrivateKey clientKey, final char[] keyStorePassphrase, final Certificate[] trustedCertificates) {
    this.clientKey = clientKey;
    this.clientCertificateChain = clientCertificateChain;
    this.keyStorePassphrase = keyStorePassphrase;
    this.trustedCertificates = trustedCertificates;
  }

  /**
   * Generates the necessary context for initializing an {@link java.net.http.HttpClient HttpClient} configured for mTLS.
   *
   * @return a context configured with this object's mTLS parameters (client certificate, client key, and trust anchors)
   *
   * @throws NoSuchAlgorithmException if the default protocol, <code>TLSv1.3</code>, is not supported on this system
   */
  public SSLContext context() throws NoSuchAlgorithmException {
    return context(TLS_1_3);
  }

  /**
   * Generates the necessary context for initializing an {@link java.net.http.HttpClient HttpClient} configured for mTLS.
   *
   * @param protocol A supported algorithm name from the list of <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#sslcontext-algorithms"><code>SSLContext</code> Algorithms</a>.
   *
   * @return a context configured with this object's mTLS parameters (client certificate, client key, and trust anchors)
   *
   * @throws NoSuchAlgorithmException if the given <code>protocol</code> is not supported on this system
   */
  public SSLContext context(final String protocol) throws NoSuchAlgorithmException {
    SSLContext context = SSLContext.getInstance(protocol);

    try {
      context.init(keyManagers(), trustManagers(), secureRandom());
    } catch (KeyManagementException impossible) {
      // We're managing this whole process, so we know it won't explode.
    }

    return context;
  }

  private KeyStore emptyKeyStore() {
    try {
      KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

      try {
        keyStore.load(null, null);
      } catch (IOException impossible) {
        // We aren't even loading anything.
      } catch (CertificateException impossible) {
        // We aren't even loading anything.
      } catch (NoSuchAlgorithmException impossible) {
        // We aren't even loading anything.
      }

      return keyStore;
    } catch (KeyStoreException impossible) {
      // We are using the the keystore's default type. Come on, now.
    }

    return null;
  }

  private KeyManager[] keyManagers() {
    try {
      KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

      try {
        factory.init(keyStore(), keyStorePassphrase);
      } catch (KeyStoreException impossible) {
        // We literally just created the keystore. It's fine.
      } catch (UnrecoverableKeyException impossible) {
        // Our keyStorePassphrase is guaranteed to be correct because we are generating the keystore on-the-fly with it
      }

      return factory.getKeyManagers();
    } catch (NoSuchAlgorithmException impossible) {
      // We are using the KMF's own default algorithm. Come on, now.
    }

    return new KeyManager[0];
  }

  private KeyStore keyStore() {
    KeyStore keyStore = emptyKeyStore();

    try {
      keyStore.setKeyEntry(ALIAS_CLIENT, clientKey, keyStorePassphrase, clientCertificateChain);
    } catch (KeyStoreException impossible) {
      // By the time we get here, there is no reason for this to ever happen.
    }

    return keyStore;
  }

  private SecureRandom secureRandom() throws NoSuchAlgorithmException {
    return SecureRandom.getInstance(DRBG, DrbgParameters.instantiation(256, DrbgParameters.Capability.PR_AND_RESEED, getClass().getName().getBytes(Charset.forName(UTF8))));
  }

  private TrustManager[] trustManagers() {
    try {
      TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

      try {
        factory.init(trustStore());
      } catch (KeyStoreException impossible) {
        // There's no reason why this should actually fail.
      }

      return factory.getTrustManagers();
    } catch (NoSuchAlgorithmException impossible) {
      // We are using the TMF's own default algorithm. Come on, now.
    }

    return new TrustManager[0];
  }

  private KeyStore trustStore() {
    KeyStore trustStore = emptyKeyStore();

    for (int index = 0; index < trustedCertificates.length; index++) {
      try {
        trustStore.setCertificateEntry(String.format("%s-%d", ALIAS_SERVER, index), trustedCertificates[index]);
      } catch (KeyStoreException impossible) {
        // By the time we get here, there is no reason for this to ever happen.
      }
    }

    return trustStore;
  }
}
