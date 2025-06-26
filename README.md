# RSA-PSS Digital Signature - Python Implementation

## Requirements
- Python 3.7+
- unittest library
- random library
- hashlib library (for sha256)

## How to Run

1. Run `rsa_pss.py` to see a basic signature/verify demo.
2. Run `test_rsa_pss.py` to execute unit tests.

## What It Does
- Generates RSA key pair
- Signs a message using RSA-PSS padding and SHA-256
- Verifies the signature
- Includes unit tests for various cases
