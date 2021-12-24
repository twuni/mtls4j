package dev.twuni.mtls4j;

import static org.junit.Assert.assertNotNull;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import org.junit.Test;

public class PEMTest implements Examples {
  @Test
  public void parseCertificate_whenGivenValidInput_returnsNonNull() throws CertificateException {
    assertNotNull(PEM.parseCertificate(EXAMPLE_CERTIFICATE));
  }

  @Test
  public void parsePrivateKey_whenGivenValidInput_returnsNonNull() throws InvalidKeySpecException, NoSuchAlgorithmException {
    assertNotNull(PEM.parsePrivateKey(EXAMPLE_PRIVATE_KEY));
  }
}
