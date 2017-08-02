package org.hypoport.jwk.transcoder;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.File;
import java.io.FileReader;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

import static java.lang.System.in;
import static java.nio.charset.StandardCharsets.UTF_8;

public class PemToJwkTranscoder {

  public static void main(String[] argv) throws Exception {
    String pem;
    if (argv.length == 0 || Objects.equals(argv[0], "-")) {
      pem = IOUtils.toString(in, UTF_8);
    } else if (argv[0].matches("^[./~]")) {
      pem = IOUtils.toString(new FileReader(new File(argv[0])));
    } else {
      pem = argv[0];
    }
    Object object = new PEMParser(new StringReader(pem)).readObject();
    if (object instanceof SubjectPublicKeyInfo) {
      PublicKey publicKey = new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) object);
      if (publicKey instanceof ECPublicKey) {
        System.out.println(
            new ECKey.Builder(ECKey.Curve.forECParameterSpec(((ECPublicKey) publicKey).getParams()), (ECPublicKey) publicKey)
                .build().toJSONString());
      } else if (publicKey instanceof RSAPublicKey) {
        System.out.println(
            new RSAKey.Builder((RSAPublicKey) publicKey).build().toJSONString());
      }
    } else if (object instanceof PEMKeyPair) {
      KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) object);
      if (keyPair.getPrivate() instanceof ECPrivateKey) {
        System.out.println(
            new ECKey.Builder(ECKey.Curve.forECParameterSpec(((ECPublicKey) keyPair.getPublic()).getParams()), (ECPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .build().toJSONString());
      }
      if (keyPair.getPrivate() instanceof RSAPrivateKey) {
        System.out.println(
            new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .build().toJSONString());
      }
    }
  }
}
