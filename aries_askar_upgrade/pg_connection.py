import asyncpg
import base64

from urllib.parse import urlparse

from .db_connection import DbConnection
from .error import UpgradeError


class PgConnection(DbConnection):
    """Postgres connection."""

    DB_TYPE = "pgsql"

    def __init__(
        self, db_host: str, db_name: str, db_user: str, db_pass: str
    ) -> "PgConnection":
        """Initialize a PgConnection instance."""
        self._config = {
            "host": db_host,
            "db": db_name,
            "user": db_user,
            "password": db_pass,
        }
        self._conn: asyncpg.Connection = None

    @property
    def parsed_url(self):
        """Accessor for the parsed database URL."""
        url = self._config["host"]
        if "://" not in url:
            url = f"http://{url}"
        return urlparse(url)

    async def connect(self):
        """Accessor for the connection pool instance."""
        if not self._conn:
            parts = self.parsed_url
            self._conn = await asyncpg.connect(
                host=parts.hostname,
                port=parts.port or 5432,
                user=self._config["user"],
                password=self._config["password"],
                database=self._config["db"],
            )

    async def find_table(self, name: str) -> bool:
        """Check for existence of a table."""
        found = await self._conn.fetch(
            """
                SELECT EXISTS
                (
                    SELECT FROM information_schema.tables
                    WHERE table_name = $1
                )
            """,
            name,
        )
        return found[0][0]

    async def pre_upgrade(self) -> dict:
        """Add new tables and columns."""

        if not await self.find_table("metadata"):
            raise UpgradeError("No metadata table found: not an Indy wallet database")

        if await self.find_table("config"):
            stmt = await self._conn.fetch("SELECT name, value FROM config")
            config = {}
            for row in stmt:
                config[row[0]] = row[1]
            return config

        async with self._conn.transaction():

            await self._conn.execute(
                """
                CREATE TABLE config (
                    name TEXT NOT NULL,
                    value TEXT,
                    PRIMARY KEY (name)
                );
                """
            )
            await self._conn.execute(
                """
                CREATE TABLE profiles (
                    id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    reference TEXT NULL,
                    profile_key BYTEA NULL,
                    PRIMARY KEY (id)
                );
                """
            )
            await self._conn.execute(
                """
                CREATE UNIQUE INDEX ix_profile_name ON profiles (name);
                """
            )
            await self._conn.execute(
                """
                ALTER TABLE items RENAME TO items_old;
                """
            )
            await self._conn.execute(
                """
                CREATE TABLE items (
                    id INTEGER NOT NULL,
                    profile_id INTEGER NOT NULL,
                    kind INTEGER NOT NULL,
                    category BYTEA NOT NULL,
                    name BYTEA NOT NULL,
                    value BYTEA NOT NULL,
                    expiry TIMESTAMP NULL,
                    PRIMARY KEY (id),
                    FOREIGN KEY (profile_id) REFERENCES profiles (id)
                        ON DELETE CASCADE ON UPDATE CASCADE
                );
                """
            )
            await self._conn.execute(
                """
                CREATE UNIQUE INDEX ix_items_uniq ON items
                    (profile_id, kind, category, name);
                """
            )
            await self._conn.execute(
                """
                CREATE TABLE items_tags (
                    id INTEGER NOT NULL,
                    item_id INTEGER NOT NULL,
                    name BYTEA NOT NULL,
                    value BYTEA NOT NULL,
                    plaintext BOOLEAN NOT NULL,
                    PRIMARY KEY (id),
                    FOREIGN KEY (item_id) REFERENCES items (id)
                        ON DELETE CASCADE ON UPDATE CASCADE
                );
                """
            )
            await self._conn.execute(
                """
                CREATE INDEX ix_items_tags_item_id ON items_tags (item_id);
                """
            )
            await self._conn.execute(
                """
                CREATE INDEX ix_items_tags_name_enc ON items_tags
                    (name, SUBSTR(value, 1, 12)) WHERE plaintext=False;
                """
            )
            await self._conn.execute(
                """
                CREATE INDEX ix_items_tags_name_plain ON items_tags
                    (name, value) WHERE plaintext=True;

                COMMIT;
            """,
            )
        return {}

    async def insert_profile(self, pass_key: str, name: str, key: bytes):
        """Insert the initial profile."""
        await self._conn.executemany(
            "INSERT INTO config (name, value) VALUES ($1, $2)",
            [
                ("default_profile", name),
                ("key", pass_key),
            ],
        )
        await self._conn.execute(
            "INSERT INTO profiles (name, profile_key) VALUES ($1, $2)",
            (name, key),
        )
        await self._conn.commit()

    async def finish_upgrade(self):
        """Complete the upgrade."""

    async def fetch_one(self, postgres: str, optional: bool = False):
        """Fetch a single row from the database."""
        stmt: str = await self._conn.fetch(postgres)
        found = None
        for row in stmt:
            decoded = (base64.b64decode(bytes.decode(row[0])),)
            if found is None:
                found = decoded
            else:
                raise Exception("Found duplicate row")
        if optional or found:
            return found
        else:
            raise Exception("Row not found")

    async def fetch_pending_items(self, limit: int):
        """Fetch un-updated items."""

    async def update_items(self, items):
        """Update items in the database."""

    async def close(self):
        """Release the connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None
