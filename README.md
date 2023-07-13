# Novo Chain File Inscription Script

This Python script allows you to inscribe files onto the Novo chain by breaking them into chunks and embedding them in Novo transactions. It also handles encryption of the file data if an encryption password is provided.

## Features

- File chunking: Breaks the file into 42KB chunks and embeds each chunk in a separate Novo transaction.
- File encryption: If an encryption password is provided, the script encrypts the file data before embedding it in transactions.
- Logging: Logs all significant events to a log file, including the transaction IDs of each transaction created.

## Usage

To use this script, run it from the command line with the following syntax:

```
python upload.py <file_path> <your_address> <encryption_password>
```

Where:

- `<file_path>` is the path to the file you want to inscribe onto the Novo chain.
- `<your_address>` is your Novo address. This will be used as the sender and recipient of the transactions.
- `<encryption_password>` is an optional argument. If provided, this password will be used to encrypt the file data.

The script will then proceed to chunk and encrypt the file (if an encryption password was provided), create and broadcast the necessary transactions, and log all significant events to a log file.

## Requirements

This script requires a running Novo node with an active RPC server. The node URL and RPC credentials are hardcoded in the script and should be modified as needed. 

## Output

The output of the script will be a JSON file stored in the `inscriptions` directory. This file contains important information about the inscription process, including the transaction IDs of all transactions created, the unique identifier assigned to the file, and the final inscription ID.

The script also logs all significant events to a log file. The location of this log file is printed to the console at the start of the script.

## Warning

This script is experimental and should be used with caution. The user is responsible for all content inscribed onto the Novo chain using this tool. Furthermore, the use of this tool implies agreement that Novo tokens and NFTs have no inherent value and are not investments.

## Contribution

Feel free to contribute to this project by making a pull request. All contributions are appreciated!
