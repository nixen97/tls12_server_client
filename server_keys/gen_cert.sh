#!/bin/bash

# Adapted from some IBM article

# Generate cert and priv key
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem

# Review cert
openssl x509 -text -noout -in cert.pem

