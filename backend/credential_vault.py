"""
credential_vault.py
Encrypted, session-scoped credential store.
Each session gets its own Fernet key generated at runtime.
Credentials never leave this module as plaintext.
The LLM and all other layers receive only the session_id.
"""

import threading
from cryptography.fernet import Fernet


class CredentialVault:
    """
    Thread-safe in-memory vault.
    One instance shared across the app (singleton via FastAPI lifespan).
    """

    def __init__(self):
        self._lock    = threading.Lock()
        self._keys    = {}   # session_id → Fernet key (bytes)
        self._ciphers = {}   # session_id → Fernet instance
        self._store   = {}   # session_id → {field: ciphertext}

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------
    def create_session(self, session_id: str) -> None:
        with self._lock:
            key = Fernet.generate_key()
            self._keys[session_id]    = key
            self._ciphers[session_id] = Fernet(key)
            self._store[session_id]   = {}

    def destroy_session(self, session_id: str) -> None:
        """Purge all credentials for a session. Called on export or timeout."""
        with self._lock:
            self._keys.pop(session_id, None)
            self._ciphers.pop(session_id, None)
            self._store.pop(session_id, None)

    # ------------------------------------------------------------------
    # Read / Write
    # ------------------------------------------------------------------
    def store(self, session_id: str, field: str, value: str) -> None:
        with self._lock:
            cipher = self._ciphers.get(session_id)
            if not cipher:
                raise KeyError(f"No vault for session {session_id}")
            self._store[session_id][field] = cipher.encrypt(value.encode())

    def retrieve(self, session_id: str, field: str) -> str:
        with self._lock:
            cipher = self._ciphers.get(session_id)
            if not cipher:
                raise KeyError(f"No vault for session {session_id}")
            ct = self._store[session_id].get(field)
            if ct is None:
                raise KeyError(f"Field '{field}' not found in vault for {session_id}")
            return cipher.decrypt(ct).decode()

    def store_credentials(self, session_id: str,
                          ip: str, username: str, password: str,
                          api_key: str = "") -> None:
        self.store(session_id, "ip",       ip)
        self.store(session_id, "username", username)
        self.store(session_id, "password", password)
        self.store(session_id, "api_key",  api_key)

    def get_credentials(self, session_id: str) -> dict:
        """Returns a dict with ip/username/password/api_key. Used only by audit runner."""
        return {
            "ip":       self.retrieve(session_id, "ip"),
            "username": self.retrieve(session_id, "username"),
            "password": self.retrieve(session_id, "password"),
            "api_key":  self.retrieve(session_id, "api_key"),
        }

    def has_session(self, session_id: str) -> bool:
        return session_id in self._store


# Global singleton
vault = CredentialVault()
