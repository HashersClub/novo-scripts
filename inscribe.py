import os
import sys
import base64
import json
import uuid
import logging
import subprocess
import time
import mimetypes
import requests
from math import ceil
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE = 42 * 1024
DUST_LIMIT = 5
FEE_PER_KB = 35
BLOCK_TIME = 42.0
MAX_TRIES = 100
UTXO_SLEEP_TIME = 5 
DATA_SLEEP_TIME = 60

used_utxos = []

NODE_URL = "http://127.0.0.1:8332"
RPC_USER = "NovoDockerUser"
RPC_PASSWORD = "NovoDockerPassword"

def initialize_logger():
    orderID = str(uuid.uuid4())
    log_filename = f"inscriptions/{orderID}.log"
    logging.basicConfig(filename=log_filename, filemode='w',
                        format='%(levelname)s - %(message)s', level=logging.INFO)
    return orderID

def send_rpc_request(method, params=[]):
    payload = {
        "jsonrpc": "1.0",
        "id": "python_rpc",
        "method": method,
        "params": params
    }
    headers = {'content-type': 'application/json'}
    response = requests.post(NODE_URL, auth=(RPC_USER, RPC_PASSWORD), data=json.dumps(payload), headers=headers)

    if response.status_code == 200:
        return response.json()['result']
    else:
        raise Exception(f'RPC request failed with status code {response.status_code}, response: {response.text}')

def account_balance():
    balance = send_rpc_request("getbalance")
    return float(balance)
    

def fetch_utxo(txid, sender_address):
    raw_tx = send_rpc_request("getrawtransaction", [txid])
    decoded_tx = send_rpc_request("decoderawtransaction", [raw_tx])

    for output in decoded_tx['vout']:
        if 'addresses' in output['scriptPubKey'] and output['scriptPubKey']['addresses'][0] == sender_address:
            utxo = {'txid': txid, 'vout': output['n'], 'amount': output['value']}
            return utxo

    raise Exception(f"No unused UTXO found for sender address: {sender_address}")


def perform_transactions(num_chunks, sender_address):
    utxo_txids = []
    utxos_for_chunks = []  # A new list to hold UTXO sets for each chunk
    print(num_chunks)
    for i in range(num_chunks + 1):  # Adding 1 to create an extra UTXO
        try:
            txid = send_rpc_request("sendtoaddress", [sender_address, "2000"])
            print (txid)
            utxo = fetch_utxo(txid, sender_address)

            send_rpc_request("lockunspent", [False, [utxo]])

            utxo_txids.append(utxo)

            if i < num_chunks:
                utxos_for_chunks.append([utxo])

        except Exception as e:
            logging.info(f"An error occurred while sending transactions: {str(e)}")
            
        time.sleep(UTXO_SLEEP_TIME) 
        
    final_utxo = utxo_txids.pop()  # Get the last (extra) UTXO for the final transaction

    return utxo_txids, utxos_for_chunks, final_utxo  # Also return the chunk UTXOs and the final UTXO



def check_transaction_confirmations(utxo_txids):
    all_tx_confirmed = False
    num_checks = 0

    while not all_tx_confirmed:
        num_checks += 1
        if num_checks > MAX_TRIES:
            logging.info(f"Transactions failed to confirm after {MAX_TRIES} attempts. Breaking loop...")
            break

        all_tx_confirmed = True

        for utxo_txid in utxo_txids:
            transaction_info = send_rpc_request("gettransaction", [utxo_txid['txid']])
            confirmations = transaction_info.get('confirmations', 0)
            if confirmations < 1:
                all_tx_confirmed = False

        if not all_tx_confirmed:
            logging.info(f"Not all transactions are confirmed. Waiting for {BLOCK_TIME} seconds before retrying...")
            time.sleep(BLOCK_TIME)
        else:
            logging.info("All transactions are confirmed.")

    return all_tx_confirmed


def prepare_raw_transaction(your_address, sender_address, op_return_data, utxos_for_chunk, chunk_index):
    global used_utxos  # Reference to the global list
    op_return_output = {"data": op_return_data}
    fees = round(CHUNK_SIZE / 1024 * FEE_PER_KB, 4)

    inputs = []
    input_amount = 0

    for utxo in utxos_for_chunk:
        if utxo not in used_utxos:
            used_utxos.append(utxo)  # Append used utxo to used_utxos list
            # Only add the single UTXO as an input
            inputs.append({"txid": utxo['txid'], "vout": utxo['vout']})
            input_amount += utxo['amount']

    change_amount = round(input_amount - DUST_LIMIT - fees, 4)
    print (change_amount) 
    if change_amount < 0:
        raise Exception("Insufficient funds. Please increase the UTXO amount or reduce the fee.")

    outputs = {**op_return_output, your_address: 5, sender_address: change_amount}

    raw_tx = send_rpc_request("createrawtransaction", [inputs, outputs])

    for address, amount in outputs.items():
        logging.info(f"brrr brrr gua gua")

    return raw_tx


def prepare_raw_final_transaction(your_address, sender_address, txids, final_utxo, file_path, unique_identifier, total_fees, encryption_password):
    fees = round(FEE_PER_KB, 4)

    # Generate the timestamp
    timestamp = datetime.utcnow().timestamp()

    # Retrieve file information
    file_extension = os.path.splitext(file_path)[1][1:]
    mime_type, _ = mimetypes.guess_type(file_path)
    content_type = file_extension
    content_length = os.path.getsize(file_path)
    
    # Construct the input for the final transaction
    inputs = [{"txid": final_utxo['txid'], "vout": final_utxo['vout']}]

    # Calculate the change amount
    change_amount = final_utxo['amount'] - DUST_LIMIT - fees
    print (change_amount) 
    # Raise an error if the change amount is negative
    if change_amount < 0:
        raise Exception("Insufficient funds. Please increase the UTXO amount or reduce the fee.")
        
    # Determine the encryption status
    encrypted = bool(encryption_password)

    # Create the dictionary for the OP_RETURN data
    file_extension = os.path.splitext(file_path)[1][1:]
    op_return_data = {
        "genesis_address": your_address,
        "genesis_fee": total_fees,
        "genesis_timestamp": timestamp,
        "mime_type": mime_type,
        "content_type": content_type,
        "content_length": content_length,
        "encrypted": encrypted,
        "licence": "open",
        "max_claims": 420,
        "whitelist": [], 
        "chunk_txids": txids
    }

    # Convert the OP_RETURN data to a hexadecimal string
    op_return_data_hex = json.dumps(op_return_data).encode().hex()

    # Construct the outputs dictionary with the OP_RETURN data
    outputs = {
        "data": op_return_data_hex,
        your_address: DUST_LIMIT,
        sender_address: change_amount
    }

    # Create the raw transaction
    raw_tx = send_rpc_request("createrawtransaction", [inputs, outputs])

    return raw_tx


def authenticate_raw_transaction(raw_tx):
    signed_tx = send_rpc_request("signrawtransaction", [raw_tx])
    return signed_tx["hex"]


def broadcast_raw_transaction(signed_tx):
    txid = send_rpc_request("sendrawtransaction", [signed_tx, True])
    time.sleep(DATA_SLEEP_TIME)        
    return txid


def transaction_size(signed_tx):
    decoded_tx = send_rpc_request("decoderawtransaction", [signed_tx])
    return decoded_tx["size"]

def generate_nft_contract(contract_type, max_supply, metadata, sender_address):
    token_info = send_rpc_request("createtoken", [contract_type, max_supply, metadata, sender_address])
    return token_info

def mint_nft(contract_type, token_id, token_data, sender_address):
    txid = send_rpc_request("minttoken", [contract_type, token_id, token_data, sender_address])
    return txid


def encrypt_data(data, encryption_password):
    # Encrypts the data using AES-CBC
    salt = os.urandom(16)
    iv = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000,
        backend=default_backend()
    )
    key = kdf.derive(encryption_password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return salt, iv, encrypted_data
    
def main_process():
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python upload.py <file_path> <your_address> <encryption_password>")
        sys.exit(1)

    # Generate a new address at the beginning
    sender_address = send_rpc_request("getnewaddress").strip()

    # Generate a random orderID and initialize logger
    orderID = initialize_logger()
    print(orderID)
    logging.info(f"Process orderID: {orderID}")
    
    file_path = sys.argv[1]
    your_address = sys.argv[2]
    encryption_password = sys.argv[3] if len(sys.argv) == 4 else None

    unique_identifier = str(uuid.uuid4())

    time.sleep(0.5)
    logging.info(f"Your about to inscribe {unique_identifier}")
    time.sleep(0.5)
    logging.info(f"Inscriber is {your_address}")
    time.sleep(0.5)
    logging.info(f"By using this experimental and super risky tool, you agree that NOVO, tokens and NFT worth nothing and are not investments")
    time.sleep(0.7)
    logging.info(f"If you disagree with this, you are an absolute degen")
    time.sleep(0.5)
    logging.info(f"In any case, you are responsible for the content you choose to put on chain and this tool is for educational purposes only. ")
    time.sleep(1)
    logging.info(f"Expect bugs. Let's try if it works now... ")
    
    with open(file_path, "rb") as f:
        file_data = f.read()

    num_chunks = ceil(len(file_data) / CHUNK_SIZE)
    file_type = os.path.splitext(file_path)[1][1:]
    contract_type = "NFT"
    max_supply = str(num_chunks + 1)
    fees = round(CHUNK_SIZE / 1024 * FEE_PER_KB, 4)
    total_fees = num_chunks * (DUST_LIMIT + fees + 25)
    print(total_fees)
    contract_metadata = {"id": unique_identifier, "type": file_type}
    contract_metadata_json = json.dumps(contract_metadata)

    tries = 0
    while account_balance() < total_fees:
        tries += 1
        if tries > MAX_TRIES:
            raise Exception("Pipe seems broken. Contact support.")
        logging.info(f"Waiting for funds...")
        time.sleep(BLOCK_TIME)

    utxo_txids, utxos_for_chunks, final_utxo = perform_transactions(num_chunks, sender_address)
    logging.info(f"{len(utxo_txids)} out of {num_chunks} UTXO generated.")

    # Checking confirmations
    all_tx_confirmed = check_transaction_confirmations(utxo_txids)
    if not all_tx_confirmed:
        logging.info("All transactions are not confirmed. Exiting...")
        sys.exit(1)
    else:
        logging.info("Let's inscribe this file in NOVO eternity")
    

    txids = []
    raw_transactions = []
    signed_transactions = []

    for i in range(MAX_TRIES):
        try:
            for i in range(num_chunks):
                chunk = file_data[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
                if encryption_password:
                    salt, iv, encrypted_chunk = encrypt_data(chunk, encryption_password)
                    base64_chunk = base64.b64encode(encrypted_chunk).decode()
                else:
                    base64_chunk = base64.b64encode(chunk).decode()

                hex_chunk = base64_chunk.encode().hex()

                raw_tx = prepare_raw_transaction(your_address, sender_address, hex_chunk, utxos_for_chunks[i], i)
                signed_tx = authenticate_raw_transaction(raw_tx)

                raw_transactions.append(raw_tx)
                signed_transactions.append(signed_tx)

            logging.info(f"Your file is shredded into {num_chunks} chunks. Now let's write NOVO history ..")
            
            break
        except Exception as e:
            logging.info(f"An error occurred during the transaction creation process: {str(e)}")
            if i < MAX_TRIES - 1:
                logging.info(f"Waiting {BLOCK_TIME} seconds before retrying...")
                time.sleep(BLOCK_TIME)
            else:
                raise Exception("Unable to create transactions after multiple attempts. Exiting...") from e

    for i, signed_tx in enumerate(signed_transactions):
        utxo = utxos_for_chunks[i][0]  # Get the corresponding utxo for the transaction
        send_rpc_request("lockunspent", [True, [utxo]])
        txid = broadcast_raw_transaction(signed_tx)
        logging.info(f"Chunk {i + 1}/{num_chunks}")
        logging.info(f"Transaction {i + 1}/{num_chunks} broadcasted: {txid}")
        txids.append(f'{txid}')
        
    # Create final transaction with all the txids as OP_RETURN outputs
    final_op_return_data = ' '.join(txids)
    send_rpc_request("lockunspent", [True, [{"txid": final_utxo['txid'], "vout": final_utxo['vout']}]])
    final_raw_tx = prepare_raw_final_transaction(your_address, sender_address, txids, final_utxo, file_path, unique_identifier, total_fees, encryption_password)
    final_signed_tx = authenticate_raw_transaction(final_raw_tx)
    final_txid = broadcast_raw_transaction(final_signed_tx)
    logging.info(f"Inscription ID : {final_txid}")
    logging.info(f"Save this inscription ID somewhere safe")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    result_filename = f"{orderID}.json"
    result_filepath = os.path.join(script_dir, "inscriptions", result_filename)

    result = {
        "file_name": os.path.basename(file_path),
        "extension": os.path.splitext(file_path)[1],
        "unique_identifier": unique_identifier,
        "deployer_wallet": your_address,
        "order_id": orderID,
        "number_of_chunks": num_chunks,
        "date_of_upload": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "data_transaction_ids": txids,
        "inscription_id": final_txid
    }

    inscriptions_folder = "inscriptions"
    os.makedirs(inscriptions_folder, exist_ok=True)

    with open(result_filepath, "w") as f:
        json.dump(result, f, indent=4)

if __name__ == "__main__":
    main_process()

logging.info("Script execution completed. Your file is now stored on NOVO")
