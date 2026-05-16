"""
Supabase client wrapper using direct HTTP calls (avoids pyiceberg dependency issues).
Uses the Supabase REST API directly via httpx.

WHY THIS EXISTS: The `supabase` Python package pulls in pyiceberg which
requires C++ build tools on Windows. Using raw HTTP calls is lighter,
faster, and more reliable across platforms.
"""

from typing import Optional, Dict, List, Any
from urllib.parse import quote
import httpx
from loguru import logger
from config.settings import config


class SupabaseClient:
    """
    Lightweight Supabase REST API client.
    Uses the anon key for authenticated requests to Supabase's PostgREST API.
    """
    
    def __init__(self):
        self._url: Optional[str] = None
        self._key: Optional[str] = None
        self._headers: Optional[Dict] = None
        self._initialized = False
    
    def initialize(self) -> None:
        if self._initialized:
            return
        
        self._url = config.database.supabase_url
        self._key = config.database.supabase_key
        
        if not self._url or not self._key:
            logger.warning("Supabase credentials not configured.")
            return
        
        self._headers = {
            "apikey": self._key,
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._initialized = True
        logger.info("Supabase HTTP client initialized")
    
    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Make an HTTP request to Supabase REST API."""
        if not self._initialized:
            self.initialize()
        
        url = f"{self._url}/rest/v1/{path.lstrip('/')}"
        headers = self._headers.copy()
        
        # Merge extra headers
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))
        
        with httpx.Client(timeout=30) as client:
            response = client.request(method, url, headers=headers, **kwargs)
            return response
    
    def insert(self, table: str, data: Dict[str, Any]) -> Optional[Dict]:
        """Insert a record. Returns the inserted row or None."""
        try:
            headers = {"Prefer": "return=representation"}
            r = self._request("POST", table, json=data, headers=headers)
            if r.status_code == 201:
                result = r.json()
                return result[0] if isinstance(result, list) and result else result
            logger.warning(f"Insert into {table} returned {r.status_code}: {r.text[:200]}")
            return None
        except Exception as e:
            logger.error(f"Supabase insert error in {table}: {e}")
            return None
    
    def upsert(self, table: str, data: Dict[str, Any], on_conflict: str = "content_hash") -> Optional[Dict]:
        """
        Insert with deduplication. Uses PostgreSQL ON CONFLICT.
        Returns the record if stored or already exists.
        """
        try:
            headers = {
                "Prefer": "return=representation",
                "resolution": "merge-duplicates",
            }
            r = self._request("POST", f"{table}?on_conflict={on_conflict}", 
                             json=data, headers=headers)
            if r.status_code in (200, 201):
                result = r.json()
                return result[0] if isinstance(result, list) and result else result
            # 409 = duplicate already exists (data is already in DB = success)
            if r.status_code == 409:
                return data
            logger.warning(f"Upsert into {table} returned {r.status_code}: {r.text[:200]}")
            return None
        except Exception as e:
            logger.error(f"Supabase upsert error in {table}: {e}")
            return None

    def batch_upsert(self, table: str, records: List[Dict[str, Any]], on_conflict: str = "content_hash") -> int:
        """
        Batch upsert multiple records in a single HTTP request.
        Much faster than individual upserts for large datasets.
        Returns count of successfully stored records.
        """
        if not records:
            return 0
        try:
            headers = {
                "Prefer": "return=minimal",
                "resolution": "merge-duplicates",
            }
            r = self._request("POST", f"{table}?on_conflict={on_conflict}", 
                             json=records, headers=headers)
            if r.status_code in (200, 201):
                return len(records)
            if r.status_code == 409:
                return len(records)
            logger.warning(f"Batch upsert into {table} returned {r.status_code}: {r.text[:200]}")
            return 0
        except Exception as e:
            logger.error(f"Supabase batch upsert error in {table}: {e}")
            return 0
    
    def select(self, table: str, columns: str = "*",
               filters: Optional[Dict] = None,
               limit: int = 100,
               order_by: Optional[str] = None,
               order_direction: str = "desc") -> List[Dict]:
        """Select records with optional filtering."""
        try:
            # Build query params
            params = f"select={columns}&limit={limit}"
            if order_by:
                params += f"&order={order_by}.{order_direction}"
            
            # Add filters
            if filters:
                for key, value in filters.items():
                    if isinstance(value, bool):
                        params += f"&{key}=eq.{str(value).lower()}"
                    else:
                        params += f"&{key}=eq.{quote(str(value))}"
            
            r = self._request("GET", f"{table}?{params}")
            if r.status_code == 200:
                return r.json() or []
            logger.warning(f"Select from {table} returned {r.status_code}: {r.text[:200]}")
            return []
        except Exception as e:
            logger.error(f"Supabase select error in {table}: {e}")
            return []
    
    def exists(self, table: str, field: str, value: str) -> bool:
        """Check if a record exists based on a field value."""
        try:
            params = f"select=id&{field}=eq.{quote(value)}&limit=1"
            r = self._request("GET", f"{table}?{params}")
            if r.status_code == 200:
                data = r.json()
                return len(data) > 0
            return False
        except Exception:
            return False


# Global Supabase client singleton
supabase = SupabaseClient()
