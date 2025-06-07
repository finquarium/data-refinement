import logging
import os
import requests
from refiner.config import settings

PINATA_FILE_API_ENDPOINT = "https://api.pinata.cloud/pinning/pinFileToIPFS"
PINATA_JSON_API_ENDPOINT = "https://api.pinata.cloud/pinning/pinJSONToIPFS"

def upload_json_to_ipfs(data: dict) -> str:
    """
    Uploads JSON data to IPFS using Pinata API.
    :param data: JSON data to upload (dictionary)
    :return: IPFS hash (CID)
    """
    if not settings.PINATA_API_KEY or not settings.PINATA_API_SECRET:
        logging.warning("Pinata API Key/Secret not set. Cannot upload JSON to IPFS.")
        raise ValueError("Pinata API Key/Secret not configured for IPFS upload.")

    headers = {
        "Content-Type": "application/json",
        "pinata_api_key": settings.PINATA_API_KEY,
        "pinata_secret_api_key": settings.PINATA_API_SECRET
    }

    try:
        payload = {"pinataContent": data} # Pinata expects content under pinataContent key for JSON
        response = requests.post(
            PINATA_JSON_API_ENDPOINT,
            json=payload, # Use json parameter for requests to handle serialization and Content-Type
            headers=headers,
            timeout=60 # Increased timeout for potentially larger JSON
        )
        response.raise_for_status()

        result = response.json()
        ipfs_hash = result['IpfsHash']
        logging.info(f"Successfully uploaded JSON to IPFS. CID: {ipfs_hash}")
        logging.info(f"Access at: {settings.PINATA_API_GATEWAY}/{ipfs_hash}")
        return ipfs_hash

    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while uploading JSON to IPFS: {e}")
        if e.response is not None:
            logging.error(f"Pinata Response Status: {e.response.status_code}, Body: {e.response.text}")
        raise
    except KeyError:
        logging.error(f"Key 'IpfsHash' not found in Pinata response: {response.json()}")
        raise

def upload_file_to_ipfs(file_path: str) -> str:
    """
    Uploads a file to IPFS using Pinata API.
    :param file_path: Path to the file to upload
    :return: IPFS hash (CID)
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found for IPFS upload: {file_path}")

    if not settings.PINATA_API_KEY or not settings.PINATA_API_SECRET:
        logging.warning("Pinata API Key/Secret not set. Cannot upload file to IPFS.")
        raise ValueError("Pinata API Key/Secret not configured for IPFS upload.")

    headers = {
        "pinata_api_key": settings.PINATA_API_KEY,
        "pinata_secret_api_key": settings.PINATA_API_SECRET
    }

    try:
        with open(file_path, 'rb') as file_to_upload:
            files_payload = {
                'file': (os.path.basename(file_path), file_to_upload)
            }
            response = requests.post(
                PINATA_FILE_API_ENDPOINT,
                files=files_payload,
                headers=headers,
                timeout=300 # Increased timeout for potentially larger files
            )
        response.raise_for_status() # Check for HTTP errors

        result = response.json()
        ipfs_hash = result['IpfsHash']
        logging.info(f"Successfully uploaded file '{file_path}' to IPFS. CID: {ipfs_hash}")
        logging.info(f"Access at: {settings.PINATA_API_GATEWAY}/{ipfs_hash}")
        return ipfs_hash

    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while uploading file '{file_path}' to IPFS: {e}")
        if e.response is not None:
            logging.error(f"Pinata Response Status: {e.response.status_code}, Body: {e.response.text}")
        raise
    except KeyError:
        logging.error(f"Key 'IpfsHash' not found in Pinata response: {response.json()}")
        raise

# Test with: python -m refiner.utils.ipfs (ensure .env has Pinata keys and a test file)
if __name__ == "__main__":
    if not (settings.PINATA_API_KEY and settings.PINATA_API_SECRET):
        print("PINATA_API_KEY and/or PINATA_API_SECRET not set. Skipping IPFS upload tests.")
    else:
        # Test JSON upload
        test_json_data = {"hello": "world", "version": 1}
        try:
            json_cid = upload_json_to_ipfs(test_json_data)
            print(f"Test JSON uploaded to IPFS. CID: {json_cid}")
        except Exception as e:
            print(f"Error testing JSON upload: {e}")

        # Test file upload
        if not os.path.exists(settings.OUTPUT_DIR):
            os.makedirs(settings.OUTPUT_DIR)
        test_file_path = os.path.join(settings.OUTPUT_DIR, "test_upload_file.txt")
        with open(test_file_path, "w") as f:
            f.write("This is a test file for IPFS upload.")

        try:
            file_cid = upload_file_to_ipfs(test_file_path)
            print(f"Test file '{test_file_path}' uploaded to IPFS. CID: {file_cid}")
        except Exception as e:
            print(f"Error testing file upload: {e}")
        finally:
            if os.path.exists(test_file_path):
                os.remove(test_file_path)