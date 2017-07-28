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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import java.io.Reader;

import static org.hypoport.jwt.common.Toolbox.*;

public class JWSVerifier {

  static boolean verify(SignedJWT token, Reader keyReader) throws Exception {
    return token.verify(getVerifier(token.getHeader().getAlgorithm(), keyReader));
  }

  static com.nimbusds.jose.JWSVerifier getVerifier(JWSAlgorithm algorithm, Reader keyReader) throws Exception {
    final String name = algorithm.getName();
    if (name.startsWith("RS")) {
      return new RSASSAVerifier(readRSAPublicKey(keyReader));
    }
    if (name.startsWith("ES")) {
      return new ECDSAVerifier(readECDSAPublicKey(keyReader));
    }
    if (name.startsWith("HS")) {
      return new MACVerifier(readKey(keyReader));
    }

    throw new IllegalArgumentException();
  }
}
