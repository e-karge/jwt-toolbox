package org.hypoport.jwk.transcoder;

import com.nimbusds.jose.jwk.AssymetricJWK;
import com.nimbusds.jose.jwk.JWK;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.File;
import java.io.FileReader;
import java.io.OutputStreamWriter;
import java.security.Key;
import java.util.Objects;

import static java.lang.System.in;
import static java.lang.System.out;
import static java.nio.charset.StandardCharsets.US_ASCII;

public class JwkToPemTranscoder {

  public static void main(String[] argv) throws Exception {
    JWK jwk;
    if (argv.length == 0 || Objects.equals(argv[0], "-")) {
      jwk = JWK.parse((JSONObject) JSONValue.parse(in));
    } else if (argv[0].matches("^[./~]")) {
      jwk = JWK.parse((JSONObject) JSONValue.parse(new FileReader(new File(argv[0]))));
    } else {
      jwk = JWK.parse((JSONObject) JSONValue.parse(argv[0]));
    }
    if (jwk instanceof AssymetricJWK) {
      Key key = ((AssymetricJWK) jwk).toPrivateKey();
      if (key == null) {
        key = ((AssymetricJWK) jwk).toPublicKey();
      }
      try (JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(out, US_ASCII))) {
        pemWriter.writeObject(key);
      }
    } else {
      throw new UnsupportedOperationException("Incompatible JWK type: " + jwk.getKeyType());
    }
  }
}
