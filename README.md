# Vana Data Refiner for Finquarium Financial Data

This repository is a customized version of the Vana Data Refinement template, specifically designed to process and refine output data from the Finquarium proof-of-contribution system. It transforms JSON-based financial transaction data (e.g., from Coinbase, Binance) into a normalized and queryable SQLite database, suitable for the Vana ecosystem.

## Overview

This data refiner takes a JSON file (typically `results.json` or similar, as output by a Finquarium PoC job) containing user financial data and transforms it into a structured SQLite database. The process involves:

1.  **Input Validation**: Checking if the input JSON matches the expected financial data structure. It will skip files that appear to be survey-type data (identifiable by top-level keys like `metadata` and `expertise`).
2.  **Parsing Input**: Reading the valid financial data JSON which contains user details, summary statistics, and a list of transactions.
3.  **Data Transformation**: Mapping the input JSON data to a predefined relational schema. This includes creating tables for users, financial statistics, individual transactions, and user assets.
4.  **Database Creation**: Storing the transformed data in a libSQL (SQLite compatible) database.
5.  **Encryption**: Symmetrically encrypting the resulting SQLite database file using a key derived from the original file's encryption key (provided by the Vana refinement service).
6.  **IPFS Upload (Optional)**: If configured with Pinata credentials, the encrypted database and its schema definition are uploaded to IPFS.

The refined, encrypted database can then be registered with the Vana Data Registry, making the structured financial information queryable by permitted entities within the Vana ecosystem.

## Refined Database Schema

The refinement process generates a SQLite database with the following main tables:

*   **`users`**: Stores the unique `id_hash` for each user and the `file_id` (if provided by the environment) associated with the input data.
*   **`user_financial_stats`**: Contains aggregated statistics for each user, such as `total_volume`, `transaction_count`, `unique_assets_count`, `activity_period_days`, and date ranges. Linked to `users`.
*   **`transactions`**: Lists individual financial transactions, including `type`, `asset`, `quantity`, `native_amount`, and `timestamp`. Linked to `users`.
*   **`user_assets`**: Stores a record for each unique asset a user has transacted with. Linked to `users`.

For detailed column information, refer to `refiner/models/refined.py`.

## Project Structure

(See Project Structure section above in the thought block)

## Getting Started

1.  **Clone/Fork this Repository**: This repository contains the refiner logic tailored for Finquarium.
2.  **Input Data**: Place an example `results.json` file (or a similarly structured JSON file from the Finquarium PoC) into the `input/` directory. An example is provided.
3.  **Environment Variables**:
    *   Create a `.env` file in the root of the project or set environment variables directly.
    *   The most important ones for local testing are `REFINEMENT_ENCRYPTION_KEY` (any string for testing) and optionally `PINATA_API_KEY` and `PINATA_API_SECRET` if you want to upload to IPFS via Pinata.
    *   The `FILE_ID` environment variable can be set to simulate the value injected by the Vana refinement service.
    *   See the "Environment Variables" section in `refiner/config.py` or the example below.
4.  **Build and Test**: Follow the "Local Development" instructions.

### Example `.env` file:
```dotenv
# Local directories where inputs and outputs are found.
INPUT_DIR=input
OUTPUT_DIR=output

# This key is derived from the user file's original encryption key,
# automatically injected into the container by the Vana refinement service.
# When developing locally, any non-empty string can be used here for testing.
REFINEMENT_ENCRYPTION_KEY=finquarium_local_test_key

# Schema details are set in refiner/config.py for Finquarium by default
# SCHEMA_NAME="Finquarium User Transactions"
# SCHEMA_VERSION="1.0.0"
# SCHEMA_DESCRIPTION="Refined schema for user financial transaction data..."
# SCHEMA_DIALECT="sqlite"

# Optional: File ID, normally injected by the Vana refinement service
FILE_ID=12345

# Optional, required if using https://pinata.cloud (IPFS pinning service)
# If not provided, IPFS uploads will be skipped and output.refinement_url will be a local file:// path.
# PINATA_API_KEY=your_pinata_api_key
# PINATA_API_SECRET=your_pinata_api_secret