package org.hypoport.jwk.transcoder;

import com.nimbusds.jose.jwk.AssymetricJWK;
import com.nimbusds.jose.jwk.JWK;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.security.Key;

import static java.lang.System.out;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

public class JwkToPemTranscoder {

  public static void main(String[] argv) throws Exception {
    InputStreamReader reader = new InputStreamReader(System.in, UTF_8);
    StringWriter writer = new StringWriter();
    IOUtils.copy(reader, writer);
    JWK jwk = JWK.parse(writer.toString());
    if (jwk instanceof AssymetricJWK) {
      Key key = ((AssymetricJWK) jwk).toPrivateKey();
      if (key == null) {
        key = ((AssymetricJWK) jwk).toPublicKey();
      }
      try (JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(out, US_ASCII))) {
        pemWriter.writeObject(key);
      }
    } else {
      throw new UnsupportedOperationException("Incompatible JWK");
    }
  }
}
