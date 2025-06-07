import json
import logging
import os

from refiner.models.offchain_schema import OffChainSchema
from refiner.models.output import Output
from refiner.transformer.finquarium_transformer import FinquariumTransformer # Updated import
from refiner.config import settings
from refiner.utils.encrypt import encrypt_file
from refiner.utils.ipfs import upload_file_to_ipfs, upload_json_to_ipfs

# Import Pydantic models for input validation
from refiner.models.unrefined import FinquariumDataUnrefined, SurveyDataUnrefined
from pydantic import ValidationError


class Refiner:
    def __init__(self):
        self.db_path = os.path.join(settings.OUTPUT_DIR, 'db.libsql')
        if not os.path.exists(settings.OUTPUT_DIR):
            os.makedirs(settings.OUTPUT_DIR, exist_ok=True)

    def _is_survey_data(self, data: dict) -> bool:
        """Checks if the data structure matches the survey data type."""
        try:
            SurveyDataUnrefined.model_validate(data)
            return True
        except ValidationError:
            return False

    def _is_finquarium_tx_data(self, data: dict) -> bool:
        """Checks if the data structure matches the Finquarium transaction data type."""
        try:
            FinquariumDataUnrefined.model_validate(data)
            return True
        except ValidationError:
            return False

    def transform(self) -> Output:
        """Transform all input files into the database."""
        logging.info("Starting data transformation for Finquarium Data")
        output = Output() # Initializes with output_schema=None and refinement_url=None

        processed_files = 0
        input_file_path = None # To store the path of the file being processed

        # List contents of the input directory
        logging.info(f"Input directory contents: {os.listdir(settings.INPUT_DIR)}")

        # Assuming only one relevant JSON file (e.g. results.json) in the input directory
        for input_filename in os.listdir(settings.INPUT_DIR):
            current_file_path = os.path.join(settings.INPUT_DIR, input_filename)
            if os.path.isfile(current_file_path) and os.path.splitext(current_file_path)[1].lower() == '.json' or os.path.splitext(current_file_path)[1].lower() == '.pgp':
                input_file_path = current_file_path # Found our JSON
                logging.info(f"Processing input file: {input_filename}")
                break # Process only the first JSON file found

        if not input_file_path:
            logging.warning("No JSON file found in the input directory.")
            return output # Return empty output

        with open(input_file_path, 'r') as f:
            try:
                input_data = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON from {input_file_path}: {e}")
                return output # Return empty output if JSON is malformed

            # Validate data type and skip if it's survey data
            if self._is_survey_data(input_data):
                logging.info(f"Skipping file {input_filename} as it appears to be survey data.")
                return output # Skip this file, return empty output

            if not self._is_finquarium_tx_data(input_data):
                logging.warning(f"Skipping file {input_filename} as it does not match expected Finquarium transaction data structure.")
                return output # Skip this file, return empty output

            # If we reach here, it's valid Finquarium transaction data
            try:
                transformer = FinquariumTransformer(self.db_path) # This initializes/clears the DB
                transformer.process(input_data) # This processes and saves data
                logging.info(f"Successfully transformed data from {input_filename}")
                processed_files += 1
            except Exception as e:
                logging.error(f"Error transforming data from {input_filename}: {e}", exc_info=True)
                return output # Return empty on transformation error


        if processed_files > 0:
            # Generate and set the schema definition in the output object
            try:
                schema_sql = transformer.get_schema() # Get SQL schema from transformer
                schema_obj = OffChainSchema(
                    name=settings.SCHEMA_NAME,
                    version=settings.SCHEMA_VERSION,
                    description=settings.SCHEMA_DESCRIPTION,
                    dialect=settings.SCHEMA_DIALECT,
                    schema=schema_sql
                )
                output.output_schema = schema_obj

                # Save the schema.json locally
                schema_file_path = os.path.join(settings.OUTPUT_DIR, 'schema.json')
                with open(schema_file_path, 'w') as sf:
                    json.dump(schema_obj.model_dump(mode='json'), sf, indent=4) # Use mode='json' for Pydantic v2
                logging.info(f"Schema definition saved to {schema_file_path}")

                # Upload the schema to IPFS if Pinata credentials are provided
                if settings.PINATA_API_KEY and settings.PINATA_API_SECRET:
                    try:
                        schema_ipfs_hash = upload_json_to_ipfs(schema_obj.model_dump(mode='json'))
                        logging.info(f"Schema uploaded to IPFS. CID: {schema_ipfs_hash}")
                        # Vana typically expects the schema IPFS URL to be registered on-chain separately,
                        # not necessarily part of this output.json, but good to log.
                    except Exception as e:
                        logging.error(f"Failed to upload schema to IPFS: {e}")
                else:
                    logging.info("Pinata API Key/Secret not set. Skipping IPFS upload for schema.")
            except Exception as e:
                logging.error(f"Error generating or saving schema: {e}", exc_info=True)


            # Encrypt and (optionally) upload the database to IPFS
            try:
                if not settings.REFINEMENT_ENCRYPTION_KEY:
                    logging.error("REFINEMENT_ENCRYPTION_KEY is not set. Cannot encrypt the database.")
                    # Decide behavior: fail, or provide unencrypted path?
                    # For Vana, encryption is usually mandatory.
                    output.refinement_url = f"error:encryption_key_missing"
                else:
                    encrypted_path = encrypt_file(settings.REFINEMENT_ENCRYPTION_KEY, self.db_path)
                    logging.info(f"Database encrypted to: {encrypted_path}")

                    if settings.PINATA_API_KEY and settings.PINATA_API_SECRET:
                        try:
                            ipfs_hash = upload_file_to_ipfs(encrypted_path)
                            # Use the full gateway URL
                            output.refinement_url = f"{settings.PINATA_API_GATEWAY.rstrip('/')}/{ipfs_hash}"
                            logging.info(f"Encrypted database uploaded to IPFS. URL: {output.refinement_url}")
                        except Exception as e:
                            logging.error(f"Failed to upload refined database to IPFS: {e}")
                            output.refinement_url = f"file://{encrypted_path}" # Fallback to local file path
                    else:
                        logging.info("Pinata API Key/Secret not set. Skipping IPFS upload for refined database.")
                        output.refinement_url = f"file://{encrypted_path}" # Local file path if not uploaded
            except Exception as e:
                logging.error(f"Error during database encryption or upload: {e}", exc_info=True)
                if output.refinement_url is None: # If not already set to an error or fallback
                    output.refinement_url = f"error:encryption_upload_failed"

        elif processed_files == 0 and input_file_path : # A file was found but not processed (e.g. skipped)
            logging.info(f"File {os.path.basename(input_file_path)} was found but not processed (e.g., skipped due to type).")

        # If output_schema is still None (e.g. no valid file processed), create a minimal one
        if output.output_schema is None:
            output.output_schema = OffChainSchema(
                name=settings.SCHEMA_NAME,
                version=settings.SCHEMA_VERSION,
                description=f"{settings.SCHEMA_DESCRIPTION} (No data processed)",
                dialect=settings.SCHEMA_DIALECT,
                schema="NO_DATA_PROCESSED"
            )
            if output.refinement_url is None:
                output.refinement_url = "NO_DATA_PROCESSED"


        logging.info(f"Data transformation run completed. Output: {output.model_dump_json(indent=2, exclude_none=True)}")
        return output