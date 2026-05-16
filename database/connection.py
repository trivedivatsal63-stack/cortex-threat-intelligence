"""
Database connection management for Supabase PostgreSQL.
Provides both sync (SQLAlchemy) and async connections.
Uses connection pooling for production performance.

WHY THIS EXISTS: Centralized database connection management ensures
connections are properly pooled, reused, and closed. Prevents
connection leaks and provides a consistent interface for all modules.
"""

from contextlib import contextmanager, asynccontextmanager
from typing import AsyncGenerator, Generator, Optional
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from loguru import logger

from config.settings import config


class DatabaseManager:
    """
    Manages database connections and provides access methods.
    Uses SQLAlchemy for sync operations.
    """
    
    def __init__(self):
        self._engine = None
        self._session_maker = None
        self._initialized = False
    
    def initialize(self) -> None:
        """
        Initialize the database connection pool.
        Must be called before any database operations.
        """
        if self._initialized:
            return
        
        db_url = config.database.database_url
        if not db_url:
            logger.warning("DATABASE_URL not configured. Database features disabled.")
            return
        
        try:
            self._engine = create_engine(
                db_url,
                poolclass=QueuePool,
                pool_size=config.database.pool_size,
                max_overflow=config.database.max_overflow,
                pool_pre_ping=True,  # Verify connections before use
                pool_recycle=3600,   # Recycle connections after 1 hour
                echo=config.debug,
            )
            self._session_maker = sessionmaker(
                bind=self._engine,
                autocommit=False,
                autoflush=False,
            )
            self._initialized = True
            logger.info("Database connection pool initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """
        Get a database session via context manager.
        Automatically commits on success, rolls back on error.
        
        Usage:
            with db.get_session() as session:
                session.execute(text("SELECT 1"))
        """
        if not self._initialized:
            self.initialize()
        
        session: Session = self._session_maker()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def execute(self, query, params=None):
        """Execute a query directly."""
        with self.get_session() as session:
            result = session.execute(text(query), params)
            return result
    
    def fetch_all(self, query, params=None) -> list:
        """Fetch all rows from a query."""
        with self.get_session() as session:
            result = session.execute(text(query), params)
            return result.fetchall()
    
    def fetch_one(self, query, params=None):
        """Fetch a single row from a query."""
        with self.get_session() as session:
            result = session.execute(text(query), params)
            return result.fetchone()
    
    def insert(self, table: str, data: dict) -> Optional[dict]:
        """
        Insert a row into a table.
        Returns the inserted row or None on failure.
        """
        columns = ", ".join(data.keys())
        placeholders = ", ".join([f":{k}" for k in data.keys()])
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders}) RETURNING *"
        
        with self.get_session() as session:
            result = session.execute(text(query), data)
            row = result.fetchone()
            if row:
                return dict(row._mapping)
            return None
    
    def upsert(self, table: str, data: dict, conflict_column: str, update_columns: list = None) -> Optional[dict]:
        """
        Insert or update a row (UPSERT).
        Used for deduplication - updates existing row if conflict.
        """
        if update_columns is None:
            update_columns = [k for k in data.keys() if k != conflict_column]
        
        update_set = ", ".join([f"{c} = EXCLUDED.{c}" for c in update_columns])
        columns = ", ".join(data.keys())
        placeholders = ", ".join([f":{k}" for k in data.keys()])
        
        query = f"""
            INSERT INTO {table} ({columns}) 
            VALUES ({placeholders}) 
            ON CONFLICT ({conflict_column}) 
            DO UPDATE SET {update_set}
            RETURNING *
        """
        
        with self.get_session() as session:
            result = session.execute(text(query), data)
            row = result.fetchone()
            if row:
                return dict(row._mapping)
            return None
    
    def close(self) -> None:
        """Close the database connection pool."""
        if self._engine:
            self._engine.dispose()
            logger.info("Database connection pool closed")
            self._initialized = False
    
    @property
    def is_connected(self) -> bool:
        """Check if database is initialized and reachable."""
        if not self._initialized:
            return False
        try:
            with self.get_session() as session:
                session.execute(text("SELECT 1"))
            return True
        except Exception:
            return False


# Global database manager singleton
db = DatabaseManager()
