"""Migraciones de la BD stego con el rol stego_owner (spec §7.6, §23.7)."""

from shared.migrations import run

run("stego")
