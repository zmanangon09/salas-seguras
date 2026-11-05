"""Migraciones de la BD auth con el rol auth_owner (spec §7.6)."""

from shared.migrations import run

run("auth")
