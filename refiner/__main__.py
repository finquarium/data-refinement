import json
import logging
import os
import sys

from refiner.refine import Refiner
from refiner.config import settings

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def run() -> None:
    """Transform all input files into the database."""

    # Create output directory if it doesn't exist
    if not os.path.exists(settings.OUTPUT_DIR):
        os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
        logging.info(f"Created output directory: {settings.OUTPUT_DIR}")

    input_files_exist = os.path.isdir(settings.INPUT_DIR) and bool(os.listdir(settings.INPUT_DIR))

    if not input_files_exist:
        logging.error(f"No input files found in {settings.INPUT_DIR}")
        # Create an empty output.json to signal completion without processing
        output_path = os.path.join(settings.OUTPUT_DIR, "output.json")
        with open(output_path, 'w') as f:
            json.dump({"refinement_url": "NO_INPUT_FILES", "output_schema": {"name": settings.SCHEMA_NAME, "version": settings.SCHEMA_VERSION, "description": "No input files found", "dialect": settings.SCHEMA_DIALECT, "schema": "NO_INPUT_FILES"}}, f, indent=2)
        sys.exit(1) # Exit with error if no input


    # Initialize and run the refiner
    try:
        refiner = Refiner()
        output_data = refiner.transform() # This now returns an Output Pydantic model
    except Exception as e:
        logging.error(f"Critical error during data transformation pipeline: {e}", exc_info=True)
        # Attempt to write a failure output.json
        output_path = os.path.join(settings.OUTPUT_DIR, "output.json")
        with open(output_path, 'w') as f:
            json.dump({"refinement_url": f"ERROR_TRANSFORMING:{str(e)}", "output_schema": {"name": settings.SCHEMA_NAME, "version": settings.SCHEMA_VERSION, "description": f"Error during transformation: {str(e)}", "dialect": settings.SCHEMA_DIALECT, "schema": f"ERROR_TRANSFORMING:{str(e)}"}}, f, indent=2)
        sys.exit(1)

    # Save the final output (output.json)
    output_json_path = os.path.join(settings.OUTPUT_DIR, "output.json")
    try:
        with open(output_json_path, 'w') as f:
            # Use Pydantic's model_dump_json for proper serialization
            f.write(output_data.model_dump_json(indent=2, exclude_none=True))
        logging.info(f"Refinement process complete. Final output written to: {output_json_path}")
    except Exception as e:
        logging.error(f"Error writing final output.json: {e}", exc_info=True)
        # Fallback to simple dict if Pydantic model failed for some reason (should not happen)
        with open(output_json_path, 'w') as f:
            json.dump({"refinement_url": "ERROR_WRITING_OUTPUT_JSON", "output_schema": {"name":settings.SCHEMA_NAME, "description": "Error during final JSON write"}}, f, indent=2)
        sys.exit(1)


if __name__ == "__main__":
    run()