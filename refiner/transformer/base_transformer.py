from typing import Dict, Any, List
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from refiner.models.refined import Base # Ensure this points to your refined models Base
import sqlite3
import os
import logging

class DataTransformer:
    """
    Base class for transforming JSON data into SQLAlchemy models.
    Users should extend this class and override the transform method
    to customize the transformation process for their specific data.
    """

    def __init__(self, db_path: str):
        """Initialize the transformer with a database path."""
        self.db_path = db_path
        self._initialize_database()

    def _initialize_database(self) -> None:
        """
        Initialize or recreate the database and its tables.
        """
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
                logging.info(f"Deleted existing database at {self.db_path}")
            except OSError as e:
                logging.error(f"Error deleting existing database {self.db_path}: {e}")

        self.engine = create_engine(f'sqlite:///{self.db_path}')
        Base.metadata.create_all(self.engine) # Creates tables based on refined.py
        self.Session = sessionmaker(bind=self.engine)

    def transform(self, data: Dict[str, Any]) -> List[Base]:
        """
        Transform JSON data into SQLAlchemy model instances.

        Args:
            data: Dictionary containing the JSON data

        Returns:
            List of SQLAlchemy model instances to be saved to the database
        """
        raise NotImplementedError("Subclasses must implement transform method")

    def get_schema(self) -> str:
        """
        Extracts the SQL schema (CREATE TABLE statements) from the generated SQLite database.

        Returns:
            A string containing all CREATE TABLE statements.
        """
        if not os.path.exists(self.db_path):
            logging.warning(f"Database file {self.db_path} does not exist. Cannot extract schema.")
            # Attempt to create schema by initializing DB if it wasn't already
            self._initialize_database()
            if not os.path.exists(self.db_path): # Still doesn't exist
                return "Schema generation failed: DB not created."


        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        schema_parts = []
        try:
            # Get all table definitions in order (important for foreign keys)
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            tables_sql = cursor.fetchall()
            for table_sql_tuple in tables_sql:
                if table_sql_tuple[0]:
                    schema_parts.append(table_sql_tuple[0] + ";")

            # Get index definitions (optional, but good for completeness)
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            indexes_sql = cursor.fetchall()
            for index_sql_tuple in indexes_sql:
                if index_sql_tuple[0]: # Check if sql is not None
                    schema_parts.append(index_sql_tuple[0] + ";")

        except sqlite3.Error as e:
            logging.error(f"SQLite error while extracting schema: {e}")
            return f"Error extracting schema: {e}"
        finally:
            conn.close()

        return "\n\n".join(schema_parts)

    def process(self, data: Dict[str, Any]) -> None:
        """
        Process the data transformation and save to database.

        Args:
            data: Dictionary containing the JSON data
        """
        session = self.Session()
        try:
            # Transform data into model instances
            models_to_save = self.transform(data)
            if models_to_save: # Only add if there are models
                session.add_all(models_to_save) # Use add_all for efficiency
                session.commit()
            else:
                logging.info("Transform method returned no models to save.")
        except Exception as e:
            session.rollback()
            logging.error(f"Error during data processing/saving: {e}", exc_info=True)
            raise
        finally:
            session.close()