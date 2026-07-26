"""
Drop the obsolete private.refreshtoken table.

Required when upgrading to the session-based authentication release. JWT
refresh tokens were replaced by session tokens in private.accounttoken
(created automatically by create_all() on startup), and SQLModel
create_all() does not drop tables that no longer have models. Run this
against any local or deployed database that predates session auth.

Upgrading logs every user out either way: the old JWT cookies stop being
accepted the moment the new code deploys.

Usage:
    uv run python -m migrations.drop_refresh_tokens .env
    uv run python -m migrations.drop_refresh_tokens .env --apply
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from dotenv import load_dotenv
from sqlalchemy import text
from sqlmodel import Session, create_engine

from utils.core.db import get_connection_url

OBSOLETE_TABLE = "refreshtoken"


@dataclass
class MigrationStats:
    table_exists: bool = False


def _table_exists(session: Session) -> bool:
    result = session.connection().execute(
        text(
            """
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'private'
              AND table_name = :table_name
            """
        ),
        {"table_name": OBSOLETE_TABLE},
    )
    return result.first() is not None


def drop_refresh_token_table(env_file: str, apply: bool) -> MigrationStats:
    load_dotenv(env_file, override=True)
    engine = create_engine(get_connection_url())
    stats = MigrationStats()

    try:
        with Session(engine) as session:
            stats.table_exists = _table_exists(session)

            if apply and stats.table_exists:
                session.connection().execute(
                    text(f"DROP TABLE private.{OBSOLETE_TABLE}")
                )
                session.commit()
            else:
                session.rollback()
    finally:
        engine.dispose()

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Drop the obsolete private.refreshtoken table left behind by the "
            "JWT-to-sessions migration. Without --apply, runs in dry-run mode."
        )
    )
    parser.add_argument("env", help="Env file to use (e.g. .env)")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the schema change (default is dry-run).",
    )
    args = parser.parse_args()

    stats = drop_refresh_token_table(env_file=args.env, apply=args.apply)
    mode = "APPLY" if args.apply else "DRY-RUN"
    if not stats.table_exists:
        print(f"[{mode}] private.{OBSOLETE_TABLE} does not exist; nothing to do.")
        return

    if args.apply:
        print(f"[{mode}] private.{OBSOLETE_TABLE} dropped.")
    else:
        print(
            f"[{mode}] private.{OBSOLETE_TABLE} exists. "
            "Re-run with --apply to drop it."
        )


if __name__ == "__main__":
    main()
