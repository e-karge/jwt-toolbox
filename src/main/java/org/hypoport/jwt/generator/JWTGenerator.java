/*
Copyright (c) 2014 Hypoport AG

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

package org.hypoport.jwt.generator;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.Header;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileReader;
import java.util.Objects;

import static java.lang.System.in;
import static java.nio.charset.StandardCharsets.UTF_8;
import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;

public class JWTGenerator {

  public static void main(String[] argv) throws Exception {
    final JSONObject header = (JSONObject) new JSONParser(DEFAULT_PERMISSIVE_MODE).parse(argv[0]);
    final Algorithm algorithm = Header.parseAlgorithm(header);

    final String payload;
    if (Objects.equals(argv[1], "-")) {
      payload = IOUtils.toString(in, UTF_8);
    } else if (argv[1].matches("^[./~]")) {
      payload = IOUtils.toString(new FileReader(new File(argv[1])));
    } else {
      payload = argv[1];
    }

    if (algorithm instanceof JWSAlgorithm) {
      System.out.println(JWSGenerator.sign(header, (JWSAlgorithm) algorithm, payload, new FileReader(argv[2])));
    }
    if (algorithm instanceof JWEAlgorithm) {
      System.out.println(JWEGenerator.encrypt(header, (JWEAlgorithm) algorithm, payload, new FileReader(argv[2])));
    }
    if (Algorithm.NONE.equals(algorithm)) {
      System.out.println(PlainGenerator.encode(header, payload));
    }
  }
}
