/*
Copyright (c) 2017 Eric Karge

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

package org.hypoport.jwt.decoder;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.hypoport.jwt.common.Toolbox;

import java.io.FileReader;

public class JWTDecoder {

  public static void main(String[] argv) throws Exception {
    JWT jwt = JWTParser.parse(argv[0]);

    System.out.println(jwt.getHeader());
    if (jwt instanceof EncryptedJWT) {
      JWEDecoder.decrypt((EncryptedJWT) jwt, new FileReader(argv[1]));
    }
    System.out.println(((JOSEObject) jwt).getPayload());
    if (jwt instanceof SignedJWT) {
      System.out.println("verified: " + (argv.length > 1 && JWSVerifier.verify((SignedJWT) jwt, new FileReader(argv[1]))));
    }
  }

  private static Algorithm getAlg(JSONObject header) {
    final Object alg = header.get("alg");
    if (alg == null) {
      return Algorithm.NONE;
    }
    if (!(alg instanceof String)) {
      throw new IllegalArgumentException("\"alg\" must be one of: \"none\",\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"RSA1_5\",\"RSA-OAEP\",\"ECDH-ES\",\"A128KW\",\"A256KW\",\"A128GCM\",\"A256GCM\"");
    }
    return Toolbox.getAlgorithmWithName((String) alg);
  }
}
