from typing import List, Dict, Any, Optional
from loguru import logger

from database.supabase_client import supabase


class EmbeddingGenerator:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model = None
        self._available = True

    def _load_model(self):
        if self._model is not None or not self._available:
            return
        try:
            from sentence_transformers import SentenceTransformer
            logger.info(f"Loading embedding model: {self.model_name}")
            self._model = SentenceTransformer(self.model_name)
            logger.info("Embedding model loaded")
        except Exception as e:
            logger.warning(f"Embedding model unavailable ({e}). Skipping embeddings.")
            self._available = False

    def encode(self, text: str) -> Optional[List[float]]:
        self._load_model()
        if not self._model:
            return None
        return self._model.encode(text, normalize_embeddings=True).tolist()

    def generate_and_store(self, table: str, records: List[Dict[str, Any]],
                           text_field: str = "title", id_field: str = "id") -> int:
        if not records:
            return 0

        self._load_model()
        if not self._model:
            return 0

        stored = 0
        for record in records:
            try:
                # Use content_hash as dedup key since DB IDs aren't available pre-insert
                content_hash = record.get("content_hash")
                if not content_hash:
                    continue

                text = f"{record.get('title', '')} {record.get('description') or record.get('ai_summary') or record.get('summary') or ''}"
                if not text.strip():
                    continue

                vector = self.encode(text[:3000])
                if not vector:
                    continue

                data = {
                    "source_table": table,
                    "source_id": content_hash,
                    "content_text": text[:2000],
                    "embedding": vector,
                    "model": self.model_name,
                    "content_hash": content_hash,
                }
                supabase.upsert("embeddings", data, on_conflict="content_hash")
                stored += 1
            except Exception as e:
                logger.warning(f"Embedding error for {table}/{record.get('content_hash', '?')}: {e}")
                continue

        return stored


embedding_generator = EmbeddingGenerator()
