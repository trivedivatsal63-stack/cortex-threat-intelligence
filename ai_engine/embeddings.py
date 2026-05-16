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
                source_id = record.get(id_field)
                if not source_id:
                    continue
                text = f"{record.get('title', '')} {record.get('description') or record.get('ai_summary') or record.get('summary') or ''}"
                if not text.strip():
                    continue

                existing = supabase.select("embeddings",
                    filters={"source_table": table, "source_id": source_id}, limit=1)
                if existing:
                    continue

                vector = self.encode(text[:3000])
                if not vector:
                    continue

                data = {
                    "source_table": table,
                    "source_id": source_id,
                    "content_text": text[:2000],
                    "embedding": vector,
                    "model": self.model_name,
                }
                supabase.insert("embeddings", data)
                stored += 1
            except Exception as e:
                logger.warning(f"Embedding error for {table}/{record.get(id_field, '?')}: {e}")
                continue

        return stored


embedding_generator = EmbeddingGenerator()
