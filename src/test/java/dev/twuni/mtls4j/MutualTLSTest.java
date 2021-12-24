package dev.twuni.mtls4j;

import static org.junit.Assert.assertNotNull;

import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import org.junit.Test;

public class MutualTLSTest implements Examples {
  @Test
  public void happyPath_returnsNonNull() throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
    assertNotNull(new MutualTLS(new Certificate[] {
      PEM.parseCertificate(EXAMPLE_CERTIFICATE)
    }, PEM.parsePrivateKey(EXAMPLE_PRIVATE_KEY), new Certificate[] {
      PEM.parseCertificate(EXAMPLE_CERTIFICATE)
    }).context());
  }
}
