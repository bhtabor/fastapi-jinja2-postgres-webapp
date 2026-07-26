"""
Drop the obsolete email-token tables.

Required when upgrading to the consolidated-token release. Password reset,
email verification, and account recovery tokens moved into
private.accounttoken (contexts "reset_password", "confirm_email", and
"recovery"), and SQLModel create_all() does not drop tables that no longer
have models. Run this against any local or deployed database that predates
the consolidation.

In-flight emailed links (reset/verification/recovery emails sent before the
upgrade) stop working: their tokens live in the dropped tables and the new
lookup is hash-based. All three token kinds are short-lived (1 hour, 1 hour,
7 days), so users simply request a fresh link.

Usage:
    uv run python -m migrations.drop_email_token_tables .env
    uv run python -m migrations.drop_email_token_tables .env --apply
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field

from dotenv import load_dotenv
from sqlalchemy import text
from sqlmodel import Session, create_engine

from utils.core.db import get_connection_url

OBSOLETE_TABLES = (
    "passwordresettoken",
    "emailverificationtoken",
    "accountrecoverytoken",
)


@dataclass
class MigrationStats:
    existing_tables: tuple[str, ...] = field(default_factory=tuple)


def _existing_obsolete_tables(session: Session) -> tuple[str, ...]:
    result = session.connection().execute(
        text(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'private'
              AND table_name = ANY(:table_names)
            """
        ),
        {"table_names": list(OBSOLETE_TABLES)},
    )
    return tuple(row[0] for row in result)


def drop_email_token_tables(env_file: str, apply: bool) -> MigrationStats:
    load_dotenv(env_file, override=True)
    engine = create_engine(get_connection_url())
    stats = MigrationStats()

    try:
        with Session(engine) as session:
            stats.existing_tables = _existing_obsolete_tables(session)

            if apply and stats.existing_tables:
                for table in stats.existing_tables:
                    session.connection().execute(
                        text(f"DROP TABLE private.{table}")
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
            "Drop the obsolete password reset, email verification, and account "
            "recovery token tables left behind by the token consolidation. "
            "Without --apply, runs in dry-run mode."
        )
    )
    parser.add_argument("env", help="Env file to use (e.g. .env)")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the schema change (default is dry-run).",
    )
    args = parser.parse_args()

    stats = drop_email_token_tables(env_file=args.env, apply=args.apply)
    mode = "APPLY" if args.apply else "DRY-RUN"
    if not stats.existing_tables:
        print(f"[{mode}] No obsolete email-token tables exist; nothing to do.")
        return

    if args.apply:
        print(f"[{mode}] Dropped: {', '.join(stats.existing_tables)}.")
    else:
        print(
            f"[{mode}] Obsolete tables present: {', '.join(stats.existing_tables)}. "
            "Re-run with --apply to drop them."
        )


if __name__ == "__main__":
    main()
