package dev.twuni.mtls4j;

import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import org.junit.Test;

public class MutualTLSTest {
  @Test
  public void whenGivenNothingMeaningful_isHarmless() throws NoSuchAlgorithmException {
    new MutualTLS(new Certificate[0], null, new Certificate[0]).context();
  }
}
