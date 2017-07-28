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

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;

import java.io.FileReader;

import static org.hypoport.jwt.common.Toolbox.readKey;
import static org.hypoport.jwt.common.Toolbox.readRSAPrivateKey;

public class JWEDecoder {

  public static void decrypt(EncryptedJWT token, FileReader keyReader) throws Exception {
    token.decrypt(getDecrypter(token.getHeader().getAlgorithm(), keyReader));
  }

  private static JWEDecrypter getDecrypter(JWEAlgorithm jweAlgorithm, FileReader keyReader) throws Exception {
    final String name = jweAlgorithm.getName();
    if (name.startsWith("RSA")) {
      return new RSADecrypter(readRSAPrivateKey(keyReader));
    }
    if (name.startsWith("ECDH")) {
      throw new UnsupportedOperationException("Elliptic curve encryption is not unsupported yet.");
    }
    if (name.startsWith("A")) {
      return new AESDecrypter(readKey(keyReader));
    }

    throw new IllegalArgumentException();
  }
}
