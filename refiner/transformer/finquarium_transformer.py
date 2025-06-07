import logging
from typing import Dict, Any, List

from refiner.models.refined import Base, User, UserFinancialStats, Transaction, UserAsset
from refiner.transformer.base_transformer import DataTransformer
from refiner.models.unrefined import FinquariumDataUnrefined # Corrected import
from refiner.utils.date import parse_timestamp
from refiner.config import settings # To get FILE_ID

logger = logging.getLogger(__name__)

class FinquariumTransformer(DataTransformer):
    """
    Transformer for Finquarium financial data.
    """

    def transform(self, data: Dict[str, Any]) -> List[Base]:
        try:
            unrefined_data = FinquariumDataUnrefined.model_validate(data)
        except Exception as e:
            logger.error(f"Failed to validate unrefined Finquarium data: {e}", exc_info=True)
            return [] # Return empty list if validation fails

        models_to_save: List[Base] = []

        # 1. Create or Get User
        # In a batch scenario, you might want to check if user exists.
        # For single file processing, creating is fine.
        # If db_path is re-initialized per call to process(), user will always be new.
        refined_user = User(
            id_hash=unrefined_data.user.id_hash,
            file_id=settings.FILE_ID # Get FILE_ID from config/env
        )
        models_to_save.append(refined_user)

        # 2. Create UserFinancialStats
        stats_unrefined = unrefined_data.stats
        try:
            first_tx_at = parse_timestamp(stats_unrefined.first_transaction_date) if stats_unrefined.first_transaction_date else None
            last_tx_at = parse_timestamp(stats_unrefined.last_transaction_date) if stats_unrefined.last_transaction_date else None
        except ValueError as e:
            logger.error(f"Error parsing transaction dates for user {unrefined_data.user.id_hash}: {e}")
            # Decide how to handle: skip stats, use None, or fail. For now, log and use None.
            first_tx_at, last_tx_at = None, None


        financial_stats = UserFinancialStats(
            user_id_hash=unrefined_data.user.id_hash, # Link to user
            total_volume=stats_unrefined.total_volume,
            transaction_count=stats_unrefined.transaction_count,
            unique_assets_count=len(stats_unrefined.unique_assets), # Calculate from the list
            activity_period_days=stats_unrefined.activity_period_days,
            first_transaction_at=first_tx_at,
            last_transaction_at=last_tx_at
        )
        models_to_save.append(financial_stats)

        # 3. Process Transactions
        for tx_unrefined in unrefined_data.transactions:
            try:
                tx_at = parse_timestamp(tx_unrefined.timestamp)
            except ValueError as e:
                logger.error(f"Error parsing transaction timestamp for user {unrefined_data.user.id_hash}, asset {tx_unrefined.asset}: {e}. Skipping transaction.")
                continue

            transaction = Transaction(
                user_id_hash=unrefined_data.user.id_hash, # Link to user
                transaction_type=tx_unrefined.type,
                asset_symbol=tx_unrefined.asset,
                quantity=tx_unrefined.quantity,
                native_amount=tx_unrefined.native_amount,
                transaction_at=tx_at
            )
            models_to_save.append(transaction)

        # 4. Process Unique Assets
        # Create UserAsset entries. This helps in querying users by assets they hold/transacted.
        processed_assets_for_user = set()
        for asset_symbol in unrefined_data.stats.unique_assets:
            if asset_symbol not in processed_assets_for_user:
                user_asset = UserAsset(
                    user_id_hash=unrefined_data.user.id_hash, # Link to user
                    asset_symbol=asset_symbol
                )
                models_to_save.append(user_asset)
                processed_assets_for_user.add(asset_symbol)

        logger.info(f"Prepared {len(models_to_save)} model instances for user {unrefined_data.user.id_hash}.")
        return models_to_save