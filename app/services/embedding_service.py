"""
Digital Guardian - Embedding Service

Provides the "embedding" step of the RAG pipeline. This uses a TF-IDF
vector space model (scikit-learn) rather than a hosted embeddings API,
so retrieval works fully offline and with zero API keys. The interface
(`EmbeddingService.embed` / `.similarity`) is intentionally provider-
agnostic: swapping this for a hosted embeddings API (OpenAI, Voyage,
Cohere, etc.) later only requires changing this one file.
"""

from typing import List

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class EmbeddingService:
    """Wraps a fitted TF-IDF vectorizer to turn text into numeric vectors."""

    def __init__(self, corpus: List[str]):
        if not corpus:
            raise ValueError("EmbeddingService requires a non-empty corpus to fit on.")
        self._vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            max_features=5000,
        )
        self._corpus_matrix = self._vectorizer.fit_transform(corpus)

    def embed_query(self, text: str) -> np.ndarray:
        """Embed a single query string into the fitted vector space."""
        return self._vectorizer.transform([text])

    def similarity_to_corpus(self, text: str) -> np.ndarray:
        """Return a 1D array of cosine similarity scores between the query and every corpus document."""
        query_vector = self.embed_query(text)
        scores = cosine_similarity(query_vector, self._corpus_matrix)
        return scores.flatten()
