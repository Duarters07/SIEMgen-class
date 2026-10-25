"""Portuguese national public holidays — used by the Director's guardrails so the
organisation goes quiet on holidays (no work events), like a real company.

Fixed-date holidays plus the movable feasts derived from Easter (computus). No
external dependency: Easter is computed with the Anonymous Gregorian algorithm.
"""
from __future__ import annotations

from datetime import date, timedelta
from functools import lru_cache

# Fixed-date national holidays (month, day).
_FIXED = {
    (1, 1): "Ano Novo",
    (4, 25): "Dia da Liberdade",
    (5, 1): "Dia do Trabalhador",
    (6, 10): "Dia de Portugal",
    (8, 15): "Assuncao de Nossa Senhora",
    (10, 5): "Implantacao da Republica",
    (11, 1): "Todos os Santos",
    (12, 1): "Restauracao da Independencia",
    (12, 8): "Imaculada Conceicao",
    (12, 25): "Natal",
}


def _easter(year: int) -> date:
    """Anonymous Gregorian algorithm (Meeus/Jones/Butcher)."""
    a = year % 19
    b, c = divmod(year, 100)
    d, e = divmod(b, 4)
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = divmod(c, 4)
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    day = ((h + l - 7 * m + 114) % 31) + 1
    return date(year, month, day)


@lru_cache(maxsize=64)
def _holidays_for_year(year: int) -> dict:
    out = {date(year, m, d): name for (m, d), name in _FIXED.items()}
    easter = _easter(year)
    out[easter - timedelta(days=2)] = "Sexta-feira Santa"
    out[easter] = "Pascoa"
    out[easter + timedelta(days=60)] = "Corpo de Deus"
    return out


def is_holiday(d) -> bool:
    """True if the given date/datetime is a PT national holiday."""
    dd = d.date() if hasattr(d, "date") else d
    return dd in _holidays_for_year(dd.year)


def holiday_name(d) -> str | None:
    dd = d.date() if hasattr(d, "date") else d
    return _holidays_for_year(dd.year).get(dd)
