# blockchain-electoral
blockchain-based electoral voting system

# Blockchain Voting System

This project is a simple implementation of a voting system using blockchain. The program securely registers votes and prevents duplication by verifying if a CPF (Brazilian ID) has already voted.

---

## Purpose

The goal of this project is to demonstrate how a blockchain can be used to sequentially and immutably store data. Each block contains the hash of the previous block, creating an unbreakable chain of records.

---

## How It Works

1. The program prompts the user to enter their CPF.
2. A SHA-256 hash is generated from the CPF to ensure privacy.
3. The user selects a candidate to vote for.
4. A new block is created with the vote hash and added to the blockchain.
5. The program checks if the CPF has already voted, preventing duplicate votes.

---

## Requirements

- A C compiler (e.g., `gcc`).
- OpenSSL library installed.

---

## Compilation and Execution

### Compile
Use the following command to compile the program:
```bash
gcc -o blockchain blockchain.c -lcrypto
```
### Run
Execute the program with:
```bash
./blockchain
```
### Usage Example
Enter a CPF (numeric only).
Choose a valid candidate number (1, 2, or 3).
After voting, the program will display the blockchain at the end.

### Code Structure
## Key Functions
- calculate_sha256: Generates a SHA-256 hash to ensure data integrity.
- create_block: Creates a new block in the blockchain.
- add_block: Adds a new block to the end of the blockchain.
- has_voted: Checks if a CPF has already voted to prevent duplication.
- print_blockchain: Prints all blocks in the blockchain.

### Limitations
- CPF Validation: The program does not validate CPF format.
- Vote Capacity: The program supports only up to 100 registered CPFs.
- Memory Management: Allocated memory for blocks and hashes is not automatically freed.

### Future Improvements
- Implement strict CPF validation.
- Expand CPF storage capacity using dynamic data structures.
- Release allocated memory at the end of the program to prevent memory leaks.
- Add support for multiple candidates and generate voting reports.

### License
This project is licensed under the MIT License. See the LICENSE file for details.

### Contributions
Contributions are welcome. Feel free to open issues or submit pull requests to this repository.

### Contact
For questions or suggestions, contact:

Author: Nícolas H Pires
Email: TeslaNode@proton.me
