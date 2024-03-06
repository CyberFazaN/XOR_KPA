"""
XOR Known Substring Attack by FazaN especially for North Palmyra (Intelligence Guild)
https://t.me/FZNSec
https://t.me/intelligence_guild
"""

import base64
import sys
from functools import partial
from typing import List, TypedDict


NULL = b"\0"
UNKNOWN = b"\xe2\x80\xa2"
NL = "\n"
CR = "\r"

class Candidate(TypedDict):  # TODO: replace with NamedTuple
    orig_pwd: bytes
    pwd: bytes
    orig_text_null: bytes
    text_null: bytes


def get_chunk(text: bytes | str, length: int, chunk_num: int) -> bytes | str:
    """
    Extracts a specific chunk from the given text based on the specified length and chunk number.

    Args:
        text (bytes | str): The original text from which to extract the chunk.
        length (int): The length of each chunk.
        chunk_num (int): The index of the chunk to retrieve (starting from 0).

    Returns:
        bytes | str: The specified chunk of the text.
    """
    start = chunk_num * length
    end = start + length
    return text[start:end]


def get_chunks(text: bytes | str, length: int) -> bytes | str:
    """
    Generates chunks of the given text based on the specified length.

    Args:
        text (bytes | str): The original text to be chunked.
        length (int): The length of each chunk.

    Yields:
        bytes | str: An iterator over all the chunks of the specified length.
    """
    return (text[i:i+length] for i in range(0, len(text), length))


def xor_cipher(ciphertext: bytes | str, password: bytes | str, null: int=1) -> bytes:
    """
    Applies the XOR cipher to the given text using the specified password and null-byte strategy.

    Args:
        ciphertext (bytes | str): The text to be encrypted or decrypted.
        password (bytes | str): The password used for XOR operations.
        null (int): The strategy for handling null bytes (1 = pure XOR, 2 = skip null bytes, 3 = keep null bytes).

    Returns:
        bytes: The result of XOR cipher.
    """
    result = bytearray()
    if hasattr(ciphertext, "encode"): ciphertext = ciphertext.encode()
    if hasattr(password, "encode"): password = password.encode()
    for i in range(len(ciphertext)):
        byte = password[i % len(password)]
        if byte != 0 or null == 1:    #pure xor
            result.append(ciphertext[i] ^ byte)
        elif null == 2:    #null skip
            continue
        elif null == 3:    #null keep
            result.append(0)
    return bytes(result)


xor_null_skip = partial(xor_cipher, null=2)
xor_null_keep = partial(xor_cipher, null=3)


def is_pwd_byte(b: bytes, symbols: bool=True) -> bool:
    """
    Checks if a byte is a valid password character, potentially including symbols.

    Args:
        b (bytes): The byte to check.
        symbols (bool): Whether to include symbols as valid password characters.

    Returns:
        bool: True if the byte is a valid password character, False otherwise.
    """
    if symbols:
        return 33 <= b <= 126
    return 48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122


def is_text_byte(b: bytes) -> bool:
    """
    Checks if a byte is a valid text character (printable ASCII character or newline).

    Args:
        b (bytes): The byte to check.

    Returns:
        bool: True if the byte is a valid text character, False otherwise.
    """
    return 32 <= b <= 126 or b == 10 or b == 13


def null_to_empty(text: bytes, placeholder=UNKNOWN) -> str:
    """
    Converts null bytes in the given text to a placeholder and decodes the text to a string.

    Args:
        text (bytes): The text containing null bytes.
        placeholder (str): The placeholder to insert instead of NULL

    Returns:
        str: The decoded text with null bytes replaced by a placeholder.
    """
    return text.replace(NULL, placeholder).decode()


def pwd_check(ciphertext: bytes | str, password: bytes | str) -> bool:
    """
    Checks whether the given password correctly decrypts the ciphertext based on XOR cipher analysis.

    Args:
        ciphertext (bytes | str): The encrypted text to check against.
        password (bytes | str): The password to use for decryption.

    Returns:
        bool: True if the password correctly decrypts the text to printable ASCII characters, False otherwise.
    """
    if hasattr(ciphertext, "encode"): ciphertext = ciphertext.encode()
    if hasattr(password, "encode"): password = password.encode()
    for chunk in get_chunks(ciphertext, len(password)):
        xored = xor_null_skip(chunk, password)
        if not all(is_text_byte(b) for b in xored):
            return False
    return True


def calc_pwds(ciphertext: bytes | str, known: bytes | str, pwd_len: int) -> List[Candidate]:
    """
    Attempts to calculate possible passwords based on a known fragment and length, testing against the ciphertext.

    Args:
        ciphertext (bytes | str): The encrypted data for which to find possible passwords.
        known (bytes | str): Known plaintext used to derive parts of the password.
        pwd_len (int): The length of the password to be tested.

    Returns:
        List[Candidate]: A list of Candidate objects representing potential decryption keys.
    """
    # Ensure input types are bytes
    ciphertext = ciphertext.encode() if isinstance(ciphertext, str) else ciphertext
    known = known.encode() if isinstance(known, str) else known
    known = known[:pwd_len] if len(known) > pwd_len else known

    result = []
    for start in range(len(ciphertext) - len(known)):  # Adjust end range to include last possible fragment
        end = start + len(known) - 1
        chunk_indices = (start // pwd_len, end // pwd_len)  # Start and end chunk indexes
        
        # Determine bytes to fill at the start and end of the known fragment
        free_at_start = pwd_len - start % pwd_len
        at_start_chunk = min(len(known), free_at_start)
        at_end_chunk = len(known) - at_start_chunk
        
        # Retrieve relevant chunks from the ciphertext
        chunks = (get_chunk(ciphertext, pwd_len, chunk_indices[0]), get_chunk(ciphertext, pwd_len, chunk_indices[1]))
        
        # Construct partial known values padded with null bytes
        known_candidate1 = b'\0' * (start % pwd_len) + known[:at_start_chunk] + b'\0' * (pwd_len - at_start_chunk - (start % pwd_len))
        known_candidate2 = known[-at_end_chunk:] + b'\0' * (pwd_len - at_end_chunk) if at_end_chunk > 0 else b'\0' * pwd_len
        
        # Check if the XOR of the known parts and chunks results in valid password bytes
        if not all(is_pwd_byte(b) for b in xor_null_skip(chunks[0], known_candidate1) + xor_null_skip(chunks[1], known_candidate2)):
            continue
        
        # Construct and validate potential passwords
        partial_pwds = [xor_null_keep(chunks[0], known_candidate1), xor_null_keep(chunks[1], known_candidate2)]
        partial_pwds[1] += b"\0" * (pwd_len - len(partial_pwds[1]))  # Fullfil left password
        merged_pwd = bytes(bytearray(partial_pwds[0][i] if partial_pwds[0][i] != 0 else partial_pwds[1][i] for i in range(len(partial_pwds[0]))))
        
        if not pwd_check(ciphertext, merged_pwd):
            continue

        # Append the successful candidate
        result.append(Candidate(orig_pwd=merged_pwd, pwd=merged_pwd, orig_text_null=xor_null_keep(ciphertext, merged_pwd), text_null=xor_null_keep(ciphertext, merged_pwd)))
    return result


# Start of end-user section


def main():
    # Display the header information
    print_header()

    # Get user inputs
    ciphertext, known, minlen, maxlen = get_user_inputs()

    # Find password candidates
    candidates = find_candidates(ciphertext, known, minlen, maxlen)

    if not candidates:
        print("[X] Sorry, I can't crack this. Maybe known substring is wrong or text contains non-ASCII characters?")
        sys.exit()

    selected_candidate = select_candidate(candidates)
    print("[I] Type \"h\" for help\n")

    while True:
        cmd_input = input("  |CMD> ").strip().split()
        if not cmd_input:
            continue

        cmd, *args = cmd_input
        if cmd == 'q':
            sys.exit()
        elif cmd == 'r':
            revert_changes(selected_candidate)
        elif cmd == 'h':
            print_help()
        elif cmd == 'w':
            print_password(selected_candidate)
        elif cmd == 'p':
            print_decrypted_text(selected_candidate, args[0] if args else True)
        elif cmd == 's':
            index = int(args[0]) if args and args[0].isdigit() else None
            selected_candidate = select_candidate(candidates, index=index)
        elif cmd == 'g':
            guess_symbol(ciphertext, selected_candidate, *args)
        elif cmd.isdigit() and len(args) > 0 and args[0].isdigit():
            guess_symbol(ciphertext, selected_candidate, cmd, *args)
        else:
            print("[!] Unrecognized command")



def print_header():
    """Prints the header information of the tool."""
    print("""|--------------------------------------------------|
# XOR Known Substring Attack                       #
# Coded by FazaN (Head Of NPTD)                    #
# Especially for                   NorthPalmyra    #
#                               Intelligence Guild #
|--------------------------------------------------|
""")


def get_user_inputs():
    """Prompts user for inputs and returns them."""
    ciphertext = base64.b64decode(input("  |Base64 Ciphertext> ").strip())
    known = input("  |Known Substring> ").strip()
    minlen = input("  |Min password length> ").strip()
    minlen = int(minlen) if minlen and minlen.isdigit() else 1
    maxlen = input("  |Max password length> ").strip()
    maxlen = int(maxlen) if maxlen and maxlen.isdigit() else min(len(ciphertext), 32)
    return ciphertext, known, minlen, maxlen


def find_candidates(ciphertext: bytes, known: str, minlen: int, maxlen: int) -> List[Candidate]:
    """Finds possible password candidates based on the given parameters."""
    candidates = []
    for pwd_len in range(minlen, maxlen + 1):
        candidates.extend(calc_pwds(ciphertext, known, pwd_len))
    return candidates


def print_candidates(candidates):
    """
    Prints all candidate passwords along with their indexes and lengths.
    """
    if candidates:
        formatted_candidates = '\n    '.join(f"{i + 1}. {null_to_empty(c['orig_pwd'])} ({len(c['orig_pwd'])})" for i, c in enumerate(candidates))
        print(f"\nFound {len(candidates)} candidates:\n    {formatted_candidates}\n")
    else:
        print("\n[!] No candidates found.\n")


def select_candidate(candidates, index=None):
    """
    Allows the user to select a candidate from the list. If the index is not provided or invalid,
    prompts the user until a valid index is entered.

    Args:
        candidates (list): The list of candidate passwords.
        index (int, optional): The pre-selected index of the candidate.

    Returns:
        dict: The selected candidate.
    """
    # List candidates if available
    print_candidates(candidates)

    while True:
        if index is None:
            index = input("  |Select candidate> ").strip()
        if isinstance(index, str):
            if index.isdigit():
                index = int(index)
            else:
                print("\n[!] Wrong candidate index!")
                index = None
                continue  # Ask for input again if not numeric
        if not isinstance(index, int):
            index = None
            continue

        # Check if the index is within the valid range
        if 1 <= index <= len(candidates):
            print(f"\n[I] Selected {null_to_empty(candidates[index - 1]['orig_pwd'])}")
            return candidates[index - 1]
        else:
            print("\n[!] Wrong candidate index!")
            index = None  # Reset index for re-input


def revert_changes(candidate):
    # Implementation of reverting changes to the candidate
    candidate['pwd'] = candidate['orig_pwd']
    candidate['text_null'] = candidate['orig_text_null']
    print("\n[I] Reverted!")

def print_help():
    # Implementation of printing help
    print("""
-----------------------------------
# Commands help:                  #
#   [arg(type)] - Addit Argument  #
#   g* - Can use without cmd code #
#                                 #
#   h - This message              #
#       h                         #
#   s - Select candidate          #
#       s [candidate_index(int)]  #
#   g* - Guess symbol             #
#       g* [row] [col] [symb]     #
#   p - Print decrypted text      #
#       p [print_as_table(bool)]  #
#   w - Print candidate password  #
#       w                         #
#   r - Revert candidate changes  #
#       r                         #
#   q - Quit program              #
#       q                         #
-----------------------------------
""")

def print_password(candidate):
    # Implementation of printing the password
    print(f"\n  Password: {null_to_empty(candidate['pwd'])}\n")

def print_decrypted_text(candidate, table_format=True, placeholder="↵"):
    """
    Prints the decrypted text stored in candidate. It can print in a regular format or in a table format based on the table_format flag.

    Args:
        candidate (dict): The candidate dictionary containing decrypted text and other information.
        table_format (bool): If True, prints the decrypted text in a table format. Otherwise, prints as plain text.
    """
    decrypted_text = null_to_empty(candidate['text_null'])
    
    # Convert string table flag to boolean if necessary
    if isinstance(table_format, str):
        table_format = table_format.lower() not in ['0', 'false', 'n']
    
    if not table_format:
        print(f"\n{decrypted_text}\n")
    else:
        password_length = len(candidate['pwd'])
        chunks = get_chunks(decrypted_text, password_length)
        
        # Preparing the header for the table
        header = '       ' + ' '.join(f"{str(i + 1):>2}" for i in range(password_length))
        print(header)
        
        # Printing each chunk in the table
        for i, chunk in enumerate(chunks, start=1):
            formatted_chunk = '  '.join(chunk.replace('\n', placeholder).replace('\r', placeholder))  # Replacing newline and carriage return for display
            print(f"{i:>7} {formatted_chunk}")
        print()  # Add an empty line for better spacing at the end

def guess_symbol(ciphertext, candidate, row=None, col=None, sym=None, *args):
    """
    Allows the user to make a guess at a symbol in the decrypted text by specifying its position and updates the password accordingly.

    Args:
        ciphertext (bytes): The encrypted data.
        candidate (dict): The current decryption candidate containing the password and decrypted text.
        row (int): The row number in the decrypted text where the symbol is guessed.
        col (int): The column number in the decrypted text where the symbol is guessed.
        sym (str): The symbol being guessed.
    """
    # Validate and get row input
    row = validate_input(row, "Row")

    # Validate and get column input
    col = validate_input(col, "Column")

    # Validate and get symbol input
    if not sym:
        sym = input("  |Symbol> ")
    if not sym:
        print("\n[X] No symbol entered!\n")
        return
    sym = sym[0]  # Use the first character of the input

    # Calculate position and validate
    pos = (row - 1) * len(candidate['pwd']) + col - 1
    if pos >= len(ciphertext):
        print("\n[X] Wrong coordinates!")
        return

    # Perform the guess operation
    guess = ciphertext[pos] ^ ord(sym)
    if not is_pwd_byte(guess):
        print("\n[X] PWD Byte check failed!")
        return

    # Update the password with the guess
    newpwd = bytearray(candidate['pwd'])
    newpwd[col - 1] = guess
    newpwd = bytes(newpwd)

    # Check if the new password works
    if not pwd_check(ciphertext, newpwd):
        print("\n[X] Decryption check failed!")
        return

    # Update the candidate with the new password and decrypted text
    candidate['pwd'] = newpwd
    candidate['text_null'] = xor_null_keep(ciphertext, newpwd)

    # Feedback to the user
    if b"\0" in newpwd:
        print("\n[+] All checks passed, password and text updated!")
    else:
        print("\n[+] IT SEEMS THAT YOU HAVE RECOVERED THE PASSWORD AND SUCCESSFULLY DECRYPTED THE TEXT!!!")
        print_password(candidate)

def validate_input(value, prompt):
    """
    Validates and retrieves the numeric input for row or column.

    Args:
        value (int): The current value of the input.
        prompt (str): The prompt to display if the value is None.

    Returns:
        int: The validated input as an integer.
    """
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    while not isinstance(value, int):
        value = input(f"  |{prompt}> ").strip()
        if not value.isdigit():
            print("\n[X] Wrong input!")
            continue
        value = int(value)
    return value



if __name__ == "__main__":
    main()
