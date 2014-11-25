package org.hypoport.jwt.generator;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;

public class JWTGenerator {

  public static void main(String[] argv) throws Exception {
    JSONObject header = (JSONObject) new JSONParser(DEFAULT_PERMISSIVE_MODE).parse(argv[0]);
    final Algorithm algorithm = getAlg(header);

    String payload = argv[1];
    String keyFile = argv[2];

    if (algorithm instanceof JWSAlgorithm) {
      JWSGenerator.sign(header, (JWSAlgorithm) algorithm, payload, keyFile);
    }
    if (algorithm instanceof JWEAlgorithm) {
      JWEGenerator.encrypt(header, (JWEAlgorithm) algorithm, payload, keyFile);
    }
  }

  private static Algorithm getAlg(JSONObject header) {
    final Object alg = header.get("alg");
    if (alg == null) {
      return JWSAlgorithm.RS512;
    }
    if (!(alg instanceof String)) {
      throw new IllegalArgumentException("\"alg\" must be one of: \"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"RSA1_5\",\"RSA-OAEP\",\"ECDH-ES\",\"A128KW\",\"A256KW\",\"A128GCM\",\"A256GCM\"");
    }
    switch ((String) alg) {
      case "HS256":
        return JWSAlgorithm.HS256;
      case "HS384":
        return JWSAlgorithm.HS384;
      case "HS512":
        return JWSAlgorithm.HS512;
      case "RS256":
        return JWSAlgorithm.RS256;
      case "RS384":
        return JWSAlgorithm.RS384;
      case "RS512":
        return JWSAlgorithm.RS512;
      case "ES256":
        return JWSAlgorithm.ES256;
      case "ES384":
        return JWSAlgorithm.ES384;
      case "ES512":
        return JWSAlgorithm.ES512;
      case "RSA1_5":
        return JWEAlgorithm.RSA1_5;
      case "RSA-OAEP":
        return JWEAlgorithm.RSA_OAEP;
      case "ECDH-ES":
        return JWEAlgorithm.ECDH_ES;
      case "A128KW":
        return JWEAlgorithm.A128KW;
      case "A256KW":
        return JWEAlgorithm.A256KW;
      case "A128GCM":
        return JWEAlgorithm.A128GCMKW;
      case "A256GCM":
        return JWEAlgorithm.A256GCMKW;
      default:
        throw new IllegalArgumentException("\"alg\" must be one of: \"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"RSA1_5\",\"RSA-OAEP\",\"ECDH-ES\",\"A128KW\",\"A256KW\",\"A128GCM\",\"A256GCM\"");
    }
  }
}