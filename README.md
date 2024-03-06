# XOR Known Substring Attack Tool

  [![Hits](https://hits.sh/github.com/CyberFazaN/XOR_KSA/hits.svg)](https://hits.sh/github.com/CyberFazaN/XOR_KSA/)

This tool, developed by FazaN for North Palmyra (Intelligence Guild), is designed to assist in the semi-automatic recovery of XOR encryption passwords through a Known Plaintext Attack (KPA). This README outlines the theoretical background, installation, usage, and functionality of the tool.

## Why Known Plaintext Attack?

The XOR operation is reversible, meaning if you have the plaintext and the ciphertext, you can easily derive the key used for encryption. This property makes XOR vulnerable to Known Plaintext Attacks, especially if the key is reused or is shorter than the message. This vulnerability stems from the cyclical nature of XOR encryption when a short key is used repeatedly.

## Installation

To use this script, you will need Python 3.6 or later. Clone the repository to your local machine using:

```bash
git clone https://github.com/CyberFazaN/XOR_KSA
```

No additional packages are required outside the standard Python library.

## Usage

Enter the project directory:

```bash
cd XOR_KSA
```

Run the script from the command line:

```bash
python xor_ksa.py
```

Follow the interactive prompts to input your Base64 encoded ciphertext, known substring, and the minimum and maximum lengths of the password you wish to recover.

## Functions Overview

- `get_chunk`: Extracts specific chunks from the given text based on length and index.
- `get_chunks`: Generates text chunks based on specified length.
- `xor_cipher`: Applies the XOR cipher based on the given password and null-byte strategy.
- `is_pwd_byte` & `is_text_byte`: Check if a byte is a valid password character or a printable text character.
- `null_to_empty`: Converts null bytes in text to a placeholder for readability.
- `pwd_check`: Validates if the guessed password can correctly decrypt the ciphertext.
- `calc_pwds`: Generates possible password candidates based on known plaintext.
- `guess_symbol`: Guessing a symbol in the text by specifying its position and updates the password accordingly.

## Contributing

Contributions to improve the tool or fix issues are welcome. Please submit a pull request or open an issue to discuss proposed changes.

## Links and Contacts

- FazaN: [Telegram](https://t.me/CyberFazaN)
- North Palmyra (Intelligence Guild): [Telegram](https://t.me/intelligence_guild)

## License

This project is open-sourced under the MIT License. See the LICENSE file for more details.

## Acknowledgments

This tool was developed as a Proof of Concept (PoC) for a research article for North Palmyra, aiming to introduce new directions such as cryptography and cryptoanalysis, steganography, and cybersecurity.
