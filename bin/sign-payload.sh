#!/bin/sh

cd "${0%/*}/.."

java -classpath target/jwt-toolbox-jar-with-dependencies.jar "org.hypoport.jwt.generator.JWTGenerator" "$@"
