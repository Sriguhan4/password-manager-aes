"""
core/generator.py
=================
Cryptographically secure password generator and strength meter.

Design decisions
----------------
1. WHY secrets, not random?
   The random module uses a Mersenne Twister PRNG which is designed for
   statistical simulation, NOT security. Its state can be reconstructed
   from 624 consecutive outputs. secrets.choice() uses os.urandom()
   (the OS CSPRNG) which is suitable for security-critical values.

2. WHY guarantee at least one character from each selected class?
   A password of length 16 chosen purely at random might miss a class
   (e.g. no symbol). By forcing at least one from each required class
   we satisfy typical website complexity requirements AND give predictable
   entropy composition. The guarantee pool is then shuffled so the
   mandatory characters don't cluster at the start.

3. WHY Fisher-Yates shuffle with secrets.randbelow?
   random.shuffle uses the Mersenne Twister and must be avoided.
   secrets.randbelow gives a uniformly distributed random integer so our
   shuffle is both unbiased and cryptographically unpredictable.

4. WHY a simple custom strength meter instead of a library?
   A library (like zxcvbn) is an external dependency. Our spec says
   "no external library for strength meter". Our metric is transparent
   and easy to explain: it counts character-class diversity and length
   tiers and maps the total score to one of five labels.
"""

import secrets
import string
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Character pools
# ---------------------------------------------------------------------------

UPPERCASE = string.ascii_uppercase          # A-Z
LOWERCASE = string.ascii_lowercase          # a-z
DIGITS    = string.digits                   # 0-9
SYMBOLS   = string.punctuation              # !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~

# Minimum and maximum allowed lengths
MIN_LENGTH = 8
MAX_LENGTH = 64


# ---------------------------------------------------------------------------
# Password Generator
# ---------------------------------------------------------------------------

def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """
    Generate a cryptographically secure random password.

    Algorithm:
      1. Validate inputs (length in range, at least one class selected).
      2. Build the full character pool from selected classes.
      3. Pick exactly one character from each selected class (guarantee step).
      4. Fill the remaining (length - num_classes) slots from the full pool.
      5. Shuffle the result using Fisher-Yates with secrets.randbelow
         so the mandatory characters don't reveal their position.
      6. Return as a string.

    Args:
        length:      Number of characters (8–64).
        use_upper:   Include A-Z.
        use_lower:   Include a-z.
        use_digits:  Include 0-9.
        use_symbols: Include punctuation.

    Returns:
        A random password string of exactly `length` characters.

    Raises:
        ValueError: If length is out of range or no character class selected.
    """
    if not (MIN_LENGTH <= length <= MAX_LENGTH):
        raise ValueError(
            f"Password length must be between {MIN_LENGTH} and {MAX_LENGTH}."
        )

    # Build list of (pool, selected) pairs
    classes = [
        (UPPERCASE, use_upper),
        (LOWERCASE, use_lower),
        (DIGITS,    use_digits),
        (SYMBOLS,   use_symbols),
    ]
    active_classes = [pool for pool, enabled in classes if enabled]

    if not active_classes:
        raise ValueError("At least one character class must be selected.")

    # Build the full character pool (all selected classes combined)
    full_pool = "".join(active_classes)

    # Step 3: guarantee at least one character from each selected class
    # WHY: ensures the password meets common complexity policies and has
    # measurable entropy from every class the user requested.
    chars: list[str] = [secrets.choice(pool) for pool in active_classes]

    # Step 4: fill remaining slots from the combined pool
    remaining = length - len(chars)
    chars += [secrets.choice(full_pool) for _ in range(remaining)]

    # Step 5: Fisher-Yates shuffle using secrets.randbelow
    # WHY not random.shuffle? See module docstring.
    _secure_shuffle(chars)

    return "".join(chars)


def _secure_shuffle(lst: list) -> None:
    """
    In-place Fisher-Yates shuffle using secrets.randbelow (constant-time safe).

    Standard Fisher-Yates: iterate from the last index down to 1,
    swap element i with a random element in [0..i].

    WHY not random.shuffle?
    random.shuffle uses the Mersenne Twister PRNG which is NOT
    cryptographically secure. secrets.randbelow uses os.urandom.
    """
    for i in range(len(lst) - 1, 0, -1):
        j = secrets.randbelow(i + 1)   # 0 <= j <= i, uniform
        lst[i], lst[j] = lst[j], lst[i]


# ---------------------------------------------------------------------------
# Strength Meter
# ---------------------------------------------------------------------------

class StrengthResult(NamedTuple):
    """Result of password_strength()."""
    score:   int    # 0–8 (higher = stronger)
    label:   str    # Human-readable label
    color:   str    # Hex colour for the GUI progress bar
    details: dict   # Breakdown of which criteria were met


# Score thresholds → (label, hex colour)
_STRENGTH_LEVELS: list[tuple[int, str, str]] = [
    # (min_score, label, colour)
    (7, "Very Strong", "#22c55e"),  # green-500
    (6, "Strong",      "#84cc16"),  # lime-500
    (5, "Moderate",    "#eab308"),  # yellow-500
    (3, "Weak",        "#f97316"),  # orange-500
    (0, "Very Weak",   "#ef4444"),  # red-500
]


def password_strength(password: str) -> StrengthResult:
    """
    Evaluate the strength of a password using a simple, transparent metric.

    Scoring (max 8 points):
      Length tiers  → +1 per tier crossed (≥8, ≥12, ≥16, ≥20)
      Uppercase     → +1 if at least one A-Z
      Lowercase     → +1 if at least one a-z
      Digit         → +1 if at least one 0-9
      Symbol        → +1 if at least one punctuation character

    WHY this metric?
    It's simple enough to explain in 30 seconds during a viva:
    "More length and more character variety = higher score."
    It maps directly to NIST SP 800-63B guidance on password composition.

    Args:
        password: The password string to evaluate.

    Returns:
        A StrengthResult NamedTuple with score (0-8), label, colour, details.
    """
    score = 0
    details: dict[str, bool] = {}

    # --- Length tiers ---
    length = len(password)
    details["len_8"]  = length >= 8;  score += int(details["len_8"])
    details["len_12"] = length >= 12; score += int(details["len_12"])
    details["len_16"] = length >= 16; score += int(details["len_16"])
    details["len_20"] = length >= 20; score += int(details["len_20"])

    # --- Character class diversity ---
    details["has_upper"]  = any(c in UPPERCASE for c in password)
    details["has_lower"]  = any(c in LOWERCASE for c in password)
    details["has_digit"]  = any(c in DIGITS    for c in password)
    details["has_symbol"] = any(c in SYMBOLS   for c in password)

    score += sum([
        details["has_upper"],
        details["has_lower"],
        details["has_digit"],
        details["has_symbol"],
    ])

    # --- Map score to label and colour ---
    label = "Very Weak"
    color = "#ef4444"
    for min_score, lbl, clr in _STRENGTH_LEVELS:
        if score >= min_score:
            label = lbl
            color = clr
            break

    return StrengthResult(score=score, label=label, color=color, details=details)
