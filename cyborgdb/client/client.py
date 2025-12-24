"""
CyborgDB REST Client

This module provides a Python client for interacting with the CyborgDB REST API.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union
import secrets
import logging
import binascii
from pydantic import ValidationError

# Import from the OpenAPI generated models
from cyborgdb.openapi_client.models import (
    IndexIVFModel as _OpenAPIIndexIVFModel,
    IndexIVFPQModel as _OpenAPIIndexIVFPQModel,
    IndexIVFFlatModel as _OpenAPIIndexIVFFlatModel,
    IndexConfig as _OpenAPIIndexConfig,
    CreateIndexRequest as _OpenAPICreateIndexRequest,
)

# Import the OpenAPI generated client
try:
    from cyborgdb.openapi_client.api_client import ApiClient, Configuration
    from cyborgdb.openapi_client.api.default_api import DefaultApi

    # Note: Model imports removed as they're accessed through the API client
    from cyborgdb.openapi_client.models.index_ivf_flat_model import IndexIVFFlatModel
    from cyborgdb.openapi_client.models.index_ivf_model import IndexIVFModel
    from cyborgdb.openapi_client.models.index_ivfpq_model import IndexIVFPQModel
    from cyborgdb.openapi_client.exceptions import ApiException
except ImportError:
    raise ImportError(
        "Failed to import openapi_client. Make sure the OpenAPI client library is properly installed."
    )

from cyborgdb.client.encrypted_index import EncryptedIndex
from cyborgdb.client.exceptions import (
    CyborgDBConnectionError,
    CyborgDBValidationError,
    CyborgDBAuthenticationError,
    CyborgDBNotFoundError,
    CyborgDBIndexError,
    CyborgDBInvalidKeyError,
    CyborgDBInvalidURLError,
)

logger = logging.getLogger(__name__)

__all__ = [
    "Client",
    "EncryptedIndex",
    "IndexConfig",
    "IndexIVF",
    "IndexIVFPQ",
    "IndexIVFFlat",
]


def _validate_url(url: str) -> None:
    """
    Validate that the provided URL is a valid HTTP/HTTPS URL.

    Args:
        url: The URL string to validate

    Raises:
        CyborgDBInvalidURLError: If the URL is invalid
    """
    if not isinstance(url, str):
        raise CyborgDBInvalidURLError(
            f"base_url must be a string, got {type(url).__name__}", url=url
        )

    url = url.strip()
    if not url:
        raise CyborgDBInvalidURLError("base_url cannot be empty", url=url)

    # Check if URL starts with http:// or https://
    if not (url.startswith("http://") or url.startswith("https://")):
        raise CyborgDBInvalidURLError(
            "base_url must start with 'http://' or 'https://'", url=url
        )

    # Basic validation: try to parse as URL
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if not parsed.netloc:
            raise CyborgDBInvalidURLError(
                f"Invalid URL format: missing host/domain in '{url}'", url=url
            )
    except Exception as e:
        if isinstance(e, CyborgDBInvalidURLError):
            raise
        raise CyborgDBInvalidURLError(f"Invalid URL format: {e}", url=url)

# Re-export with friendly names
IndexIVF = _OpenAPIIndexIVFModel
IndexIVFPQ = _OpenAPIIndexIVFPQModel
IndexIVFFlat = _OpenAPIIndexIVFFlatModel
IndexConfig = _OpenAPIIndexConfig
CreateIndexRequest = _OpenAPICreateIndexRequest


class Client:
    """
    Client for interacting with CyborgDB via REST API.

    This class provides methods for creating, loading, and managing encrypted indexes.
    """

    def __init__(
        self, base_url: str, api_key: Optional[str] = None, verify_ssl: Optional[bool] = None
    ):
        """
        Initialize the CyborgDB client.

        Args:
            base_url: The base URL of the CyborgDB service (e.g., 'https://api.cyborg.co' or 'http://localhost:8000')
            api_key: Optional API key for authentication
            verify_ssl: Optional SSL verification setting. If None, auto-detects based on URL.
                        For localhost/127.0.0.1, SSL verification is disabled by default.

        Raises:
            CyborgDBInvalidURLError: If the base_url is invalid
            CyborgDBConnectionError: If the client fails to initialize
        """
        # Validate URL
        _validate_url(base_url)

        # If base_url is http, disable SSL verification
        if base_url.startswith("http://"):
            verify_ssl = False

        # Set up the OpenAPI client configuration
        self.config = Configuration()
        self.config.host = base_url

        # Configure SSL verification
        if verify_ssl is None:
            # Auto-detect: disable SSL verification for localhost/127.0.0.1 (development)
            if "localhost" in base_url or "127.0.0.1" in base_url:
                self.config.verify_ssl = False
                # Disable SSL warnings for localhost
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                logger.info(
                    "SSL verification disabled for localhost (development mode)"
                )
            else:
                self.config.verify_ssl = True
        else:
            self.config.verify_ssl = verify_ssl
            if not verify_ssl:
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                logger.warning(
                    "SSL verification is disabled. Not recommended for production."
                )

        # Add authentication if provided
        if api_key:
            self.config.api_key = {"X-API-Key": api_key}

        # Create the API client
        try:
            self.api_client = ApiClient(self.config)
            self.api = DefaultApi(self.api_client)

            # If API key was provided, also set it directly in default headers
            if api_key:
                self.api_client.default_headers["X-API-Key"] = api_key

        except Exception as e:
            error_msg = f"Failed to initialize client: {e}"
            logger.error(error_msg)
            raise CyborgDBConnectionError(error_msg, base_url=base_url) from e

    @staticmethod
    def generate_key(save: bool = False) -> bytes:
        """
        Generate a secure 32-byte key for use with CyborgDB indexes.

        Args:
            save (bool): If True, save the key to a file in the user's home directory
                         for reuse. Not recommended for production use.
        Returns:
            bytes: A cryptographically secure 32-byte key.
        """
        if not save:
            return secrets.token_bytes(32)

        key_path = Path.home() / ".cyborgdb" / "index_key"
        key_path.parent.mkdir(parents=True, exist_ok=True)

        if key_path.exists():
            if key_path.stat().st_size == 32:
                logger.warning(
                    f"Loading existing index key from '{key_path}'.\nSaving keys is not recommended for production use."
                )
                return key_path.read_bytes()

        key = secrets.token_bytes(32)
        key_path.write_bytes(key)
        logger.warning(
            f"Generated new index key and saved to '{key_path}'.\nSaving keys is not recommended for production use."
        )
        return key

    def list_indexes(self) -> List[str]:
        """
        Get a list of all encrypted index names accessible via the client.

        Returns:
            A list of index names.

        Raises:
            CyborgDBConnectionError: If connection to the service fails
            CyborgDBAuthenticationError: If authentication fails
        """
        try:
            response = self.api.list_indexes_v1_indexes_list_get()
            return response.indexes
        except ApiException as e:
            error_msg = f"Failed to list indexes: {e}"
            logger.error(error_msg)
            # Map HTTP status codes to appropriate exceptions
            if e.status == 401 or e.status == 403:
                raise CyborgDBAuthenticationError(
                    f"Authentication failed: {error_msg}", status_code=e.status
                ) from e
            raise CyborgDBConnectionError(error_msg) from e

    def create_index(
        self,
        index_name: str,
        index_key: bytes,
        index_config: Optional[
            Union[IndexIVFModel, IndexIVFPQModel, IndexIVFFlatModel]
        ] = None,
        embedding_model: Optional[str] = None,
        metric: Optional[str] = None,
    ) -> EncryptedIndex:
        """
        Create and return a new encrypted index based on the provided configuration.
        Raises:
            CyborgDBInvalidKeyError: If index_key is invalid
            CyborgDBIndexError: If index creation fails
            CyborgDBAuthenticationError: If authentication fails
            CyborgDBValidationError: If validation fails
        """
        # Validate index_key
        if not isinstance(index_key, bytes) or len(index_key) != 32:
            raise CyborgDBInvalidKeyError()

        try:
            # Convert binary key to hex string
            key_hex = binascii.hexlify(index_key).decode("ascii")

            if index_config is None:
                index_config = IndexIVFFlatModel()  # Default config

            # Create an IndexConfig instance with the appropriate model
            index_config_obj = IndexConfig(index_config)

            # Create the complete request object
            request = CreateIndexRequest(
                index_name=index_name,
                index_key=key_hex,
                index_config=index_config_obj,
                embedding_model=embedding_model,
                metric=metric,
            )

            # Call the generated API method
            self.api.create_index_v1_indexes_create_post(
                create_index_request=request,
                _headers={
                    "X-API-Key": self.config.api_key["X-API-Key"],
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )

            return EncryptedIndex(
                index_name=index_name,
                index_key=index_key,
                api=self.api,
                api_client=self.api_client,
            )

        except ApiException as e:
            error_msg = f"Failed to create index '{index_name}': {e}"
            logger.error(error_msg)
            if e.status == 401 or e.status == 403:
                raise CyborgDBAuthenticationError(
                    f"Authentication failed: {error_msg}", status_code=e.status
                ) from e
            elif e.status == 409:
                raise CyborgDBIndexError(
                    f"Index '{index_name}' already exists", index_name=index_name
                ) from e
            raise CyborgDBIndexError(error_msg, index_name=index_name) from e
        except ValidationError as ve:
            error_msg = f"Validation error while creating index '{index_name}': {ve}"
            logger.error(error_msg)
            raise CyborgDBValidationError(error_msg) from ve

    def load_index(self, index_name: str, index_key: bytes) -> EncryptedIndex:
        """
        Load an existing encrypted index by name and key.

        Raises:
            CyborgDBInvalidKeyError: If index_key is invalid
            CyborgDBNotFoundError: If the index is not found
            CyborgDBAuthenticationError: If authentication fails
            CyborgDBValidationError: If validation fails
        """
        # Validate index_key
        if not isinstance(index_key, bytes) or len(index_key) != 32:
            raise CyborgDBInvalidKeyError()

        try:
            # Convert binary key to hex string

            index = EncryptedIndex(
                index_name=index_name,
                index_key=index_key,
                api=self.api,
                api_client=self.api_client,
            )

            # Attempt to access index.index_type to validate existence.
            # This will raise an exception if the index does not exist.
            _ = index.index_type  # Access for validation; value not used.

            # Create the EncryptedIndex instance
            return index

        except ApiException as e:
            error_msg = f"Failed to load index '{index_name}': {e}"
            logger.error(error_msg)
            if e.status == 401 or e.status == 403:
                raise CyborgDBAuthenticationError(
                    f"Authentication failed: {error_msg}", status_code=e.status
                ) from e
            elif e.status == 404:
                raise CyborgDBNotFoundError(
                    f"Index '{index_name}' not found", resource_name=index_name
                ) from e
            raise CyborgDBConnectionError(error_msg) from e
        except ValidationError as ve:
            error_msg = f"Validation error while loading index '{index_name}': {ve}"
            logger.error(error_msg)
            raise CyborgDBValidationError(error_msg) from ve

    def get_health(self) -> Dict[str, str]:
        """
        Get the health status of the CyborgDB instance.

        Returns:
            A dictionary containing health status information.

        Raises:
            CyborgDBConnectionError: If connection to the service fails
        """
        try:
            return self.api.health_check_v1_health_get()
        except ApiException as e:
            error_msg = f"Failed to get health status: {e}"
            logger.error(error_msg)
            raise CyborgDBConnectionError(error_msg) from e
