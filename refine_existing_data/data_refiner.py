import os
import time
import json
import hashlib
import hmac
import pathlib
from dotenv import load_dotenv
import requests

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pgpy

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
NETWORK = os.getenv("NETWORK", "moksha").lower()
DLP_ID = os.getenv("DLP_ID", "")
PRIVATE_KEY_HEX = os.getenv("PRIVATE_KEY")

if not DLP_ID:
    raise ValueError("DLP_ID must be set in the .env file")

if not PRIVATE_KEY_HEX:
    raise ValueError("PRIVATE_KEY must be set in the .env file")

# New Optional Features Config
DOWNLOAD_AND_DECRYPT_FILES = os.getenv("DOWNLOAD_AND_DECRYPT_FILES", "False").lower() == "true"
FILE_DOWNLOAD_PROXY_URL = os.getenv("FILE_DOWNLOAD_PROXY_URL")
DECRYPTED_FILES_OUTPUT_DIR = os.getenv("DECRYPTED_FILES_OUTPUT_DIR", "decrypted_files_output_moksha")

ENABLE_DATA_REFINEMENT = os.getenv("ENABLE_DATA_REFINEMENT", "False").lower() == "true"
DATA_REFINEMENT_DRY_RUN = os.getenv("DATA_REFINEMENT_DRY_RUN", "True").lower() == "true"
DATA_REFINEMENT_DELAY_SECONDS = float(os.getenv("DATA_REFINEMENT_DELAY_SECONDS", "1.0"))
REFINER_ID_MOKSHA = os.getenv("REFINER_ID_MOKSHA", "")
REFINER_ID_MAINNET = os.getenv("REFINER_ID_MAINNET", "")
PINATA_API_KEY = os.getenv("PINATA_API_KEY")
PINATA_API_SECRET = os.getenv("PINATA_API_SECRET")
PINATA_API_GATEWAY = os.getenv("PINATA_API_GATEWAY")

# Subgraphs for fast access to file ids
CONFIG = {
    "moksha": {
        "subgraph_url": "https://api.goldsky.com/api/public/project_cm168cz887zva010j39il7a6p/subgraphs/moksha/prod/gn",
        "block_explorer_api_url": "https://moksha.vanascan.io",
        "data_registry_contract": "0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C",
        "refinement_url": "https://a7df0ae43df690b889c1201546d7058ceb04d21b-8000.dstack-prod5.phala.network/refine",
        "refiner_id": REFINER_ID_MOKSHA
    },
    "mainnet": {
        "subgraph_url": "https://api.goldsky.com/api/public/project_cm168cz887zva010j39il7a6p/subgraphs/vana/prod/gn",
        "block_explorer_api_url": "https://vanascan.io",
        "data_registry_contract": "0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C",
        "refinement_url": "https://592387e3ed196d95ce8df7af54dab6ebca21a3c8-8000.dstack-prod5.phala.network/refine",
        "refiner_id": REFINER_ID_MAINNET
    }
}

if NETWORK not in CONFIG:
    raise ValueError(f"Invalid NETWORK: {NETWORK}. Choose 'moksha' or 'mainnet'.")

CURRENT_CONFIG = CONFIG[NETWORK]
SUBGRAPH_URL = CURRENT_CONFIG["subgraph_url"]
BLOCK_EXPLORER_API_BASE_URL = CURRENT_CONFIG["block_explorer_api_url"]
DATA_REGISTRY_CONTRACT = CURRENT_CONFIG["data_registry_contract"]
DATA_REGISTRY_QUERY_URL = f"{BLOCK_EXPLORER_API_BASE_URL}/api/v2/smart-contracts/{DATA_REGISTRY_CONTRACT}/query-read-method?is_custom_abi=false"
REFINEMENT_URL = CURRENT_CONFIG["refinement_url"]
CURRENT_REFINER_ID = CURRENT_CONFIG["refiner_id"]

if DOWNLOAD_AND_DECRYPT_FILES:
    pathlib.Path(DECRYPTED_FILES_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

# --- Helper Functions ---

def query_subgraph(query, variables=None):
    """Sends a GraphQL query to the subgraph."""
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    try:
        response = requests.post(SUBGRAPH_URL, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        if "errors" in data:
            print(f"GraphQL Error: {data['errors']}")
            return None
        return data.get("data")
    except requests.exceptions.RequestException as e:
        print(f"Error querying subgraph: {e}")
        return None
    except json.JSONDecodeError:
        print(f"Error decoding JSON response from subgraph: {response.text}")
        return None

def get_dlp_info(dlp_id: str) -> dict | None:
    """Fetches DLP information, including its address."""
    query = """
      query getDlp($dlpId: ID!) {
        dlps(where: { id: $dlpId }) {
          id
          name
          address
          website
          iconUrl
        }
      }
    """
    variables = {"dlpId": dlp_id}
    data = query_subgraph(query, variables)
    if data and data.get("dlps") and len(data["dlps"]) > 0:
        return data["dlps"][0]
    print(f"Could not find DLP with ID: {dlp_id}")
    return None

def get_all_file_ids_for_dlp(dlp_id: str) -> list[int]:
    """Fetches all file IDs for a given DLP ID, handling pagination."""
    all_file_ids = []
    page_size = 500
    skip = 0
    max_files_to_fetch_overall = 100000 # Safety break for very large DLPs
    print(f"Fetching file IDs for DLP {dlp_id} (page size: {page_size})...")

    while True:
        query = f"""
            query dataRegistryProofs {{
              dataRegistryProofs(
                where: {{dlp: "{dlp_id}"}}
                first: {page_size}
                skip: {skip}
                orderBy: fileId
                orderDirection: asc # Fetching oldest first, can be desc too
              ) {{
                fileId
              }}
            }}
          """
        data = query_subgraph(query)
        if not data or "dataRegistryProofs" not in data:
            print(f"Failed to fetch proofs or no proofs found for DLP {dlp_id} at skip {skip}.")
            break

        proofs = data["dataRegistryProofs"]
        if not proofs:
            print(f"No more file IDs found for DLP {dlp_id} after fetching {len(all_file_ids)} IDs.")
            break

        batch_file_ids = [int(proof["fileId"]) for proof in proofs]
        all_file_ids.extend(batch_file_ids)
        print(f"Fetched {len(batch_file_ids)} file IDs. Total so far: {len(all_file_ids)}.")

        if len(batch_file_ids) < page_size or len(all_file_ids) >= max_files_to_fetch_overall:
            break
        skip += page_size
        time.sleep(0.1) # Be nice to the API

    print(f"Total file IDs fetched for DLP {dlp_id}: {len(all_file_ids)}")
    return all_file_ids

def get_file_permission_py(file_id: int, account_address: str) -> str | None:
    """Gets the encrypted permission string for a file and account."""
    payload = {
        "args": [str(file_id), account_address],
        "method_id": "60f1c43a", # Corresponds to getPermission(uint256,address)
        "contract_type": "proxy",
    }
    try:
        response = requests.post(DATA_REGISTRY_QUERY_URL, json=payload, timeout=20)
        response.raise_for_status()
        data = response.json()
        if data.get("is_error") or not data.get("result") or not data["result"].get("output"):
            return None
        permission_hex = data["result"]["output"][0].get("value")
        if permission_hex and permission_hex.startswith("0x"):
            return permission_hex[2:] # Return without 0x prefix
        return permission_hex
    except requests.exceptions.RequestException as e:
        print(f"Error fetching file permission for {file_id}: {e}")
        return None
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        print(f"Error parsing permission response for file {file_id}: {e}, Response: {response.text}")
        return None

def decrypt_with_private_key_py(encrypted_data_hex: str, private_key_hex_str: str) -> str | None:
    """
    Decrypts data encrypted with ECIES (secp256k1, AES-CBC, HMAC-SHA256)
    """
    try:
        private_key_bytes = bytes.fromhex(private_key_hex_str)
        encrypted_data_bytes = bytes.fromhex(encrypted_data_hex)

        iv = encrypted_data_bytes[0:16]
        ephem_public_key_bytes = encrypted_data_bytes[16:16+65]
        ciphertext = encrypted_data_bytes[16+65:-32]
        mac_tag = encrypted_data_bytes[-32:]

        priv_key_obj = ec.derive_private_key(
            int.from_bytes(private_key_bytes, 'big'),
            ec.SECP256K1(),
            default_backend()
        )
        ephem_pub_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            ephem_public_key_bytes
        )
        shared_key = priv_key_obj.exchange(ec.ECDH(), ephem_pub_key_obj)

        hasher = hashlib.sha512()
        hasher.update(shared_key)
        derived_keys = hasher.digest()
        enc_key = derived_keys[0:32]
        mac_processing_key = derived_keys[32:64]

        data_to_mac = iv + ephem_public_key_bytes + ciphertext
        calculated_mac = hmac.new(mac_processing_key, data_to_mac, hashlib.sha256).digest()

        if not hmac.compare_digest(calculated_mac, mac_tag):
            return None

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        return decrypted_data.decode('utf-8')
    except Exception:
        return None

# --- New functions for file download and decryption ---
def get_file_details_py(file_id: int) -> dict | None:
    """Get file details (URL, owner) from the data registry contract."""
    payload = {
        "args": [str(file_id)],
        "method_id": "f4c714b4",  # Corresponds to getFile(uint256)
        "contract_type": "proxy",
    }
    try:
        response = requests.post(DATA_REGISTRY_QUERY_URL, json=payload, timeout=20)
        response.raise_for_status()
        data = response.json()

        if data.get("is_error") or not data.get("result") or \
                not data["result"].get("output") or not data["result"]["output"][0].get("value"):
            return None

        details_array = data["result"]["output"][0]["value"]
        if len(details_array) == 4:
            return {
                "id": details_array[0],
                "ownerAddress": details_array[1],
                "url": details_array[2],
                "addedAtBlock": details_array[3],
            }
        return None
    except requests.exceptions.RequestException as e:
        print(f"  Error fetching file details for {file_id}: {e}")
        return None
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        print(f"  Error parsing file details response for {file_id}: {e}, Response: {response.text}")
        return None

def download_file_content(file_url: str) -> bytes | None:
    """Downloads file content from a URL, optionally using a proxy."""
    proxies = {}
    if FILE_DOWNLOAD_PROXY_URL:
        proxies = {
            "http": FILE_DOWNLOAD_PROXY_URL,
            "https": FILE_DOWNLOAD_PROXY_URL,
        }
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
        }
        response = requests.get(file_url, proxies=proxies, headers=headers, timeout=60, stream=True)
        response.raise_for_status()
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"  Error downloading file from {file_url}: {e}")
        return None

def client_side_decrypt_py(encrypted_data: bytes, key_as_password: str) -> bytes | None:
    """Decrypts OpenPGP symmetrically encrypted data using pgpy."""
    try:
        message = pgpy.PGPMessage.from_blob(encrypted_data)

        if not message.is_encrypted:
            print("  OpenPGP Error: Message is not encrypted.")
            return None

        decrypted_message = message.decrypt(key_as_password)

        if hasattr(decrypted_message, 'message') and decrypted_message.message:
            return decrypted_message.message
        else:
            print("  OpenPGP decryption: Decrypted message object does not have expected content.")
            return None

    except pgpy.errors.PGPDecryptionError as e:
        print(f"  OpenPGP decryption error (likely wrong key or data corruption): {e}")
        return None
    except pgpy.errors.PGPError as e:
        print(f"  General OpenPGP error: {e}")
        return None
    except Exception as e:
        print(f"  Unexpected error during OpenPGP decryption: {e}")
        return None

# --- Main Execution ---
if __name__ == "__main__":
    print(f"Starting Vana Data Decryptor for DLP ID: {DLP_ID} on {NETWORK} network.")

    dlp_info = get_dlp_info(DLP_ID)
    if not dlp_info or "address" not in dlp_info:
        print(f"Could not retrieve DLP information or address for DLP ID {DLP_ID}. Exiting.")
        exit(1)

    account_address = dlp_info["address"]
    print(f"DLP Name: {dlp_info.get('name', 'N/A')}")
    print(f"DLP Address (Account Address for permissions): {account_address}")

    if DOWNLOAD_AND_DECRYPT_FILES:
        print(f"File download and decryption is ENABLED. Output dir: {DECRYPTED_FILES_OUTPUT_DIR}")
    if ENABLE_DATA_REFINEMENT:
        print(f"Data refinement is ENABLED. Dry run: {DATA_REFINEMENT_DRY_RUN}. Delay: {DATA_REFINEMENT_DELAY_SECONDS}s.")
        if not all([PINATA_API_KEY, PINATA_API_SECRET, PINATA_API_GATEWAY]):
            print("  Warning: Pinata credentials not fully configured for refinement.")


    file_ids = get_all_file_ids_for_dlp(DLP_ID)

    if not file_ids:
        print(f"No file IDs found for DLP {DLP_ID}. Exiting.")
        exit(0)

    print(f"\nFound {len(file_ids)} file IDs. Attempting to get permissions and decrypt keys...")

    stats = {
        "total_files_processed": 0,
        "successfully_decrypted_keys": 0,
        "failed_permission_fetch": 0,
        "failed_key_decryption": 0,
        "files_downloaded": 0,
        "files_decrypted": 0,
        "failed_file_download": 0,
        "failed_file_decryption": 0,
        "refinement_requests_sent": 0,
        "refinement_requests_dry_run": 0,
        "refinement_failures": 0,
    }

    output_data = []


    for i, file_id in enumerate(file_ids):
        stats["total_files_processed"] += 1
        current_file_result = {"file_id": file_id, "status_key_decryption": "pending"}
        print(f"\nProcessing file ID {file_id} ({i+1}/{len(file_ids)})...")

        permission_hex = get_file_permission_py(file_id, account_address)

        if permission_hex:
            decrypted_key = decrypt_with_private_key_py(permission_hex, PRIVATE_KEY_HEX)
            if decrypted_key:
                print(f"  SUCCESS: Decrypted key for file {file_id}: {decrypted_key}")
                stats["successfully_decrypted_keys"] += 1
                current_file_result["status_key_decryption"] = "success"
                current_file_result["decrypted_permission_key"] = decrypted_key

                if DOWNLOAD_AND_DECRYPT_FILES:
                    current_file_result["status_file_download"] = "pending"
                    current_file_result["status_file_decryption"] = "pending"
                    print(f"  Attempting to download and decrypt file {file_id}...")
                    file_details = get_file_details_py(file_id)
                    if file_details and file_details.get("url"):
                        encrypted_content = download_file_content(file_details["url"])
                        if encrypted_content:
                            stats["files_downloaded"] += 1
                            current_file_result["status_file_download"] = "success"
                            print(f"    Downloaded {len(encrypted_content)} bytes for file {file_id}.")
                            decrypted_file_bytes = client_side_decrypt_py(encrypted_content, decrypted_key)
                            if decrypted_file_bytes:
                                stats["files_decrypted"] += 1
                                current_file_result["status_file_decryption"] = "success"
                                output_file_path = pathlib.Path(DECRYPTED_FILES_OUTPUT_DIR) / f"{file_id}.decrypted"
                                try:
                                    with open(output_file_path, "wb") as df:
                                        df.write(decrypted_file_bytes)
                                    print(f"    SUCCESS: Decrypted file {file_id} and saved to {output_file_path}")
                                    current_file_result["decrypted_file_path"] = str(output_file_path)
                                except IOError as e:
                                    print(f"    ERROR: Could not write decrypted file {file_id} to disk: {e}")
                                    current_file_result["status_file_decryption"] = f"error_saving_file: {e}"
                            else:
                                stats["failed_file_decryption"] += 1
                                current_file_result["status_file_decryption"] = "failure"
                                print(f"    FAILURE: Could not decrypt downloaded file {file_id}.")
                        else:
                            stats["failed_file_download"] += 1
                            current_file_result["status_file_download"] = "failure"
                            print(f"    FAILURE: Could not download file {file_id} from {file_details.get('url')}.")
                    else:
                        stats["failed_file_download"] += 1
                        current_file_result["status_file_download"] = "no_url_found"
                        print(f"    FAILURE: Could not get URL for file {file_id} to download.")

                if ENABLE_DATA_REFINEMENT:
                    current_file_result["status_refinement"] = "pending"
                    print(f"  Attempting data refinement for file {file_id}...")

                    env_vars_payload = {
                        "PINATA_API_KEY": PINATA_API_KEY,
                        "PINATA_API_SECRET": PINATA_API_SECRET,
                        "PINATA_API_GATEWAY": PINATA_API_GATEWAY,
                    }

                    refinement_payload = {
                        "file_id": file_id,
                        "encryption_key": decrypted_key,
                        "refiner_id": int(CURRENT_REFINER_ID),
                        "env_vars": env_vars_payload
                    }

                    if DATA_REFINEMENT_DRY_RUN:
                        stats["refinement_requests_dry_run"] += 1
                        current_file_result["status_refinement"] = "dry_run_success"
                        print(f"    DRY RUN: Would send POST to {REFINEMENT_URL} with payload: {json.dumps(refinement_payload)}")
                    else:
                        try:
                            headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
                            response = requests.post(REFINEMENT_URL, json=refinement_payload, headers=headers, timeout=160)
                            response.raise_for_status()
                            stats["refinement_requests_sent"] += 1
                            current_file_result["status_refinement"] = "success"
                            current_file_result["refinement_response_status"] = response.status_code
                            print(f"    SUCCESS: Refinement request for {file_id} sent. Status: {response.status_code}")
                        except requests.exceptions.RequestException as e:
                            stats["refinement_failures"] += 1
                            current_file_result["status_refinement"] = f"failure: {e}"
                            print(f"    FAILURE: Refinement request for {file_id} failed: {e.response.text}")

                    time.sleep(DATA_REFINEMENT_DELAY_SECONDS)

            else:
                stats["failed_key_decryption"] +=1
                current_file_result["status_key_decryption"] = "failure"
                current_file_result["permission_hex"] = permission_hex
                print(f"  FAILURE: Could not decrypt key for file {file_id} (Permission: {permission_hex[:30]}...)")
        else:
            stats["failed_permission_fetch"] +=1
            current_file_result["status_key_decryption"] = "permission_fetch_failed"
            print(f"  FAILURE: Could not get permission for file {file_id}.")

        output_data.append(current_file_result)
        time.sleep(0.1)

    print("\n--- Summary ---")
    for key, value in stats.items():
        print(f"{key.replace('_', ' ').capitalize()}: {value}")

    output_filename = f"dlp_{DLP_ID}_processing_results_{NETWORK}.json"
    with open(output_filename, "w") as f:
        json.dump(output_data, f, indent=2)
    print(f"\nDetailed results saved to {output_filename}")