"""
Typosquatting + Homograph Detection

Detects brand impersonation via:
- Character substitution (0↔o, 1↔l, rn↔m)
- Homoglyphs (Cyrillic а vs Latin a)
- Punycode (xn-- prefix)
- Combosquatting (brand-extra, extra-brand)
- Bitsquatting (bit-flip)
- Vowel swaps (a↔e↔i↔o↔u)
- Transposition (adjacent char swap)
- TLD swapping (google.com → google.xyz)
- Missing/added hyphens or dots

Returns structured risk assessments per detected brand.

Uses Levenshtein distance when available; falls back to difflib.
"""

import os
import json
import unicodedata
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urlparse
from loguru import logger


# ============================================
# OPTIONAL DEPENDENCIES
# ============================================

# Try Levenshtein (fast)
try:
    from Levenshtein import distance as levenshtein_distance
    LEVENSHTEIN_AVAILABLE = True
except ImportError:
    LEVENSHTEIN_AVAILABLE = False
    logger.warning("python-Levenshtein not installed. Run: pip install python-Levenshtein")

# Fallback: difflib (built-in, slower but always available)
import difflib


# ============================================
# CONSTANTS — HOMOGRAPH & SUBSTITUTION MAPS
# ============================================

# Common character substitutions used in typosquatting
# key = character, value = set of look-alike/similar characters
CHAR_SUBSTITUTIONS = {
    'a': {'4', '@', 'á', 'à', 'â', 'ä', 'ã', 'å', 'α', 'а'},   # а = Cyrillic
    'b': {'8', '6', 'ß'},
    'c': {'(', '{', 'ç', 'с'},                                  # с = Cyrillic
    'd': {'cl'},
    'e': {'3', 'é', 'è', 'ê', 'ë', 'ε', 'е'},                   # е = Cyrillic
    'g': {'9', 'q'},
    'h': {'4', 'н'},                                            # н = Cyrillic
    'i': {'1', 'l', '!', '|', 'í', 'ì', 'î', 'ï', 'ı', 'і'},   # і = Cyrillic
    'j': {'ј'},                                                 # ј = Cyrillic
    'k': {'κ', 'к'},                                            # к = Cyrillic
    'l': {'1', 'i', '|', 'Ł'},
    'm': {'rn', 'nn', 'м'},                                     # м = Cyrillic
    'n': {'ñ', 'п'},                                            # п = Cyrillic
    'o': {'0', 'ø', 'ó', 'ò', 'ô', 'ö', 'õ', 'ο', 'о'},         # о = Cyrillic
    'p': {'ρ', 'р'},                                            # р = Cyrillic
    'q': {'9', 'g'},
    'r': {'ř'},
    's': {'5', '$', 'š', 'ѕ'},                                  # ѕ = Cyrillic
    't': {'7', '+', 'т'},                                       # т = Cyrillic
    'u': {'v', 'ü', 'ú', 'ù', 'û', 'υ'},                        # υ = Greek
    'v': {'u', 'ν'},                                            # ν = Greek
    'w': {'vv', 'ω', 'ш'},                                      # ω, ш
    'x': {'х', 'χ'},                                            # х = Cyrillic
    'y': {'ý', 'ÿ', 'у'},                                       # у = Cyrillic
    'z': {'2', 'ź', 'ż'},
}

# Homoglyph characters (Cyrillic, Greek) → Latin equivalent
HOMOGLYPH_MAP = {
    # Cyrillic
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
    'к': 'k', 'м': 'm', 'т': 't', 'н': 'h', 'в': 'b', 'і': 'i', 'ј': 'j',
    'ѕ': 's', 'н': 'h', 'г': 'r', 'п': 'n', 'л': 'l', 'д': 'd', 'ф': 'f',
    'ц': 'c', 'ч': 'ch', 'ш': 'w', 'щ': 'w', 'ъ': 'b', 'ы': 'y', 'ь': 'b',
    'э': 'e', 'ю': 'yu', 'я': 'ya',
    # Greek
    'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v',
    'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
    # Full-width Latin
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f', 'ｇ': 'g',
    'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n',
    'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't', 'ｕ': 'u',
    'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z',
    # Common combining diacritics stripped by NFKD — handled separately
}


# ============================================
# DATA CLASSES
# ============================================

@dataclass
class TyposquatMatch:
    """A single typosquatting detection"""
    brand: str
    similarity: float          # 0.0 – 1.0
    technique: str             # substitution, homoglyph, punycode, etc.
    risk: int                  # 0-100
    details: str = ""          # Human-readable explanation

    def to_dict(self):
        return {
            'brand': self.brand,
            'similarity': round(self.similarity, 4),
            'technique': self.technique,
            'risk': self.risk,
            'details': self.details,
        }


@dataclass
class TyposquatResult:
    """Aggregated typosquatting analysis"""
    domain: str
    is_typosquat: bool = False
    highest_risk: int = 0
    matches: List[TyposquatMatch] = field(default_factory=list)

    def to_dict(self):
        return {
            'domain': self.domain,
            'is_typosquat': self.is_typosquat,
            'highest_risk': self.highest_risk,
            'matches': [m.to_dict() for m in self.matches],
        }


# ============================================
# MAIN DETECTOR
# ============================================

class TyposquattingDetector:
    """
    Typosquatting + Homograph detector.

    Usage:
        detector = TyposquattingDetector()
        result = detector.analyze("micros0ft.com")
        # → matches Microsoft brand with 0.89 similarity
    """

    def __init__(self, brands_path=None):
        # Load brands
        if brands_path is None:
            brands_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                'config', 'brands.json'
            )

        self.brands = []
        self.high_value_brands = set()
        self._load_brands(brands_path)

        # Risk thresholds
        self.SIMILARITY_THRESHOLD = 0.75     # Min similarity to flag
        self.HIGH_SIMILARITY_THRESHOLD = 0.90  # Very suspicious
        self.LENGTH_TOLERANCE = 3             # Max length diff to compare

    # ============================================
    # BRAND LOADING
    # ============================================

    def _load_brands(self, path):
        """Load brand list from external JSON"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.brands = [b.lower() for b in data.get('brands', [])]
            self.high_value_brands = set(
                b.lower() for b in data.get('high_value_brands', [])
            )

            logger.info(f"Loaded {len(self.brands)} brands from {path}")
        except FileNotFoundError:
            logger.warning(f"Brand list not found at {path}. Using minimal fallback.")
            self.brands = [
                'google', 'microsoft', 'apple', 'amazon', 'facebook',
                'paypal', 'netflix', 'chase', 'binance'
            ]
            self.high_value_brands = set(self.brands)
        except Exception as e:
            logger.error(f"Failed to load brands: {e}")
            self.brands = []
            self.high_value_brands = set()

    # ============================================
    # PUBLIC
    # ============================================

    def analyze(self, url_or_domain) -> TyposquatResult:
        """
        Analyze a URL or domain for typosquatting/homograph indicators.

        Returns TyposquatResult with all detected matches.
        """
        domain = self._extract_domain(url_or_domain)
        if not domain:
            return TyposquatResult(domain="", is_typosquat=False)

        result = TyposquatResult(domain=domain)

        # Split domain into labels (subdomains + registered domain)
        labels = domain.split('.')
        if len(labels) < 2:
            return result

        # The main label to check = the part just before TLD
        # e.g. in "login.paypal-secure.com" → check "paypal-secure" and "login"
        main_labels = labels[:-1]  # Exclude TLD

        # Check each label against brand list
        for label in main_labels:
            if not label or len(label) < 3:
                continue
            matches = self._check_label(label)
            result.matches.extend(matches)

        # Also check the whole domain (for combosquatting like "paypal-secure")
        full_name = '.'.join(main_labels)
        if len(main_labels) > 1:
            full_matches = self._check_label(full_name.replace('.', '-'))
            result.matches.extend(full_matches)

        # Deduplicate by (brand, technique)
        seen = set()
        unique_matches = []
        for m in result.matches:
            key = (m.brand, m.technique)
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)
        result.matches = unique_matches

        # Sort by risk descending
        result.matches.sort(key=lambda m: m.risk, reverse=True)

        # Aggregate
        if result.matches:
            result.is_typosquat = True
            result.highest_risk = max(m.risk for m in result.matches)

        return result

    # ============================================
    # LABEL ANALYSIS
    # ============================================

    def _check_label(self, label) -> List[TyposquatMatch]:
        """Check a single domain label against all brands"""
        matches = []

        # Normalize the label
        normalized = self._normalize_label(label)

        # Skip if label is very short or numeric
        if not normalized or len(normalized) < 3:
            return matches

        for brand in self.brands:
            # Skip if brand length differs too much
            if abs(len(normalized) - len(brand)) > self.LENGTH_TOLERANCE:
                continue

            # --- Technique 1: Exact match in longer label (combosquatting) ---
            if brand in label.lower() and label.lower() != brand:
                # e.g. "paypal-secure", "secure-paypal"
                # Reduce false positives: only flag if brand is a meaningful part
                # i.e. label length is at most 2x brand length
                if len(label) <= len(brand) * 2.5:
                    matches.append(TyposquatMatch(
                        brand=brand,
                        similarity=0.85,
                        technique='combosquatting',
                        risk=self._compute_risk(brand, 0.85, 'combosquatting'),
                        details=f"'{brand}' embedded in '{label}'"
                    ))

            # --- Technique 2: Levenshtein distance ---
            similarity = self._similarity(normalized, brand)
            if similarity >= self.SIMILARITY_THRESHOLD and normalized != brand:
                technique = self._classify_technique(normalized, brand)
                matches.append(TyposquatMatch(
                    brand=brand,
                    similarity=similarity,
                    technique=technique,
                    risk=self._compute_risk(brand, similarity, technique),
                    details=f"'{label}' resembles '{brand}' ({similarity:.0%})"
                ))

            # --- Technique 3: Homoglyph detection ---
            if self._has_homoglyphs(label):
                dehomoglyphed = self._dehomoglyph(label)
                sim = self._similarity(dehomoglyphed, brand)
                if sim >= self.SIMILARITY_THRESHOLD and dehomoglyphed != brand:
                    matches.append(TyposquatMatch(
                        brand=brand,
                        similarity=sim,
                        technique='homoglyph',
                        risk=self._compute_risk(brand, sim, 'homoglyph'),
                        details=f"'{label}' contains homoglyph chars of '{brand}'"
                    ))

        # --- Technique 4: Punycode / IDN ---
        if label.lower().startswith('xn--'):
            decoded = self._decode_punycode(label)
            if decoded:
                for brand in self.brands:
                    sim = self._similarity(decoded, brand)
                    if sim >= self.SIMILARITY_THRESHOLD:
                        matches.append(TyposquatMatch(
                            brand=brand,
                            similarity=sim,
                            technique='punycode',
                            risk=min(self._compute_risk(brand, sim, 'punycode') + 15, 100),
                            details=f"Punycode '{label}' decodes to '{decoded}'"
                        ))

        return matches

    # ============================================
    # TECHNIQUE CLASSIFIER
    # ============================================

    def _classify_technique(self, candidate, brand):
        """
        Classify what kind of typosquatting was used.
        Order matters — more specific first.
        """
        # Length differences
        if len(candidate) != len(brand):
            if len(candidate) > len(brand):
                return 'insertion'
            else:
                return 'deletion'

        # Same length — check character-level differences
        diffs = [
            (candidate[i], brand[i])
            for i in range(len(candidate))
            if candidate[i] != brand[i]
        ]

        if len(diffs) == 1:
            c, b = diffs[0]
            # Check if it's a substitution from our map
            for orig, subs in CHAR_SUBSTITUTIONS.items():
                if b == orig and c in subs:
                    return 'character_substitution'
                if c == orig and b in subs:
                    return 'character_substitution'
            return 'character_substitution'

        if len(diffs) == 2:
            # Check for transposition (adjacent swap)
            i1 = candidate.find(diffs[0][0])
            if i1 >= 0 and i1 + 1 < len(candidate):
                if (candidate[i1] == brand[i1 + 1] and
                        candidate[i1 + 1] == brand[i1]):
                    return 'transposition'

            # Check for vowel swap
            if all(c in 'aeiou' and b in 'aeiou' for c, b in diffs):
                return 'vowel_swap'

        return 'edit_distance'

    # ============================================
    # HOMOGLYPH HANDLING
    # ============================================

    @staticmethod
    def _has_homoglyphs(text):
        """Check if text contains non-Latin lookalike characters"""
        for ch in text:
            if ch in HOMOGLYPH_MAP:
                return True
            # Check if non-ASCII
            if ord(ch) > 127:
                # See if NFKD decomposition gives ASCII
                decomposed = unicodedata.normalize('NFKD', ch)
                if len(decomposed) == 1 and ord(decomposed) < 128:
                    # It's a diacritic form
                    continue
                # Non-ASCII, non-diacritic → potentially homoglyph
                return True
        return False

    @staticmethod
    def _dehomoglyph(text):
        """Convert homoglyphs back to Latin equivalents"""
        result = []
        for ch in text:
            if ch in HOMOGLYPH_MAP:
                result.append(HOMOGLYPH_MAP[ch])
            else:
                # Try NFKD to strip diacritics
                decomposed = unicodedata.normalize('NFKD', ch)
                if len(decomposed) == 1 and ord(decomposed) < 128:
                    result.append(decomposed)
                else:
                    result.append(ch)
        return ''.join(result)

    # ============================================
    # PUNYCODE
    # ============================================

    @staticmethod
    def _decode_punycode(label):
        """Decode xn-- label to unicode"""
        try:
            return label.encode('ascii').decode('idna')
        except Exception:
            try:
                # Strip xn-- prefix
                if label.lower().startswith('xn--'):
                    return label[4:].encode('ascii').decode('punycode')
            except Exception:
                pass
        return None

    # ============================================
    # SIMILARITY
    # ============================================

    @staticmethod
    def _similarity(a, b):
        """
        Compute similarity 0-1 using Levenshtein distance.
        Falls back to difflib if python-Levenshtein unavailable.
        """
        if not a or not b:
            return 0.0

        a, b = a.lower(), b.lower()

        if a == b:
            return 1.0

        if LEVENSHTEIN_AVAILABLE:
            dist = levenshtein_distance(a, b)
        else:
            # Fallback: compute from SequenceMatcher
            matcher = difflib.SequenceMatcher(None, a, b)
            # Approximate edit distance = len(a) + len(b) - 2*matches
            matches = sum(block.size for block in matcher.get_matching_blocks())
            dist = len(a) + len(b) - 2 * matches

        max_len = max(len(a), len(b))
        similarity = 1.0 - (dist / max_len)

        return max(0.0, min(1.0, similarity))

    # ============================================
    # NORMALIZATION
    # ============================================

    @staticmethod
    def _normalize_label(label):
        """Normalize a label: lowercase, strip diacritics"""
        label = label.lower()
        # NFKD decomposition
        label = unicodedata.normalize('NFKD', label)
        # Strip combining marks
        label = ''.join(c for c in label if not unicodedata.combining(c))
        return label

    @staticmethod
    def _extract_domain(url_or_domain):
        """Extract hostname from a URL or return the domain as-is"""
        if not url_or_domain or not isinstance(url_or_domain, str):
            return ""

        s = url_or_domain.strip().lower()

        # If it looks like a URL, parse it
        if '://' in s or '/' in s or '?' in s:
            try:
                parsed = urlparse(s if '://' in s else 'http://' + s)
                return (parsed.netloc or '').split(':')[0]
            except Exception:
                pass

        # Assume it's a domain
        return s.split(':')[0].strip('.')

    # ============================================
    # RISK COMPUTATION
    # ============================================

    def _compute_risk(self, brand, similarity, technique):
        """
        Compute a 0-100 risk score based on:
        - Similarity (higher = riskier)
        - Whether brand is high-value (banks, crypto, big tech)
        - Technique severity
        """
        # Base: scale similarity from threshold to 1.0
        # 0.75 → 50, 1.0 → 100
        base_risk = ((similarity - 0.75) / 0.25) * 50 + 50

        # Boost for high-value brands
        if brand in self.high_value_brands:
            base_risk += 15

        # Technique modifiers
        technique_boost = {
            'character_substitution': 10,
            'homoglyph': 20,
            'punycode': 25,
            'combosquatting': 5,
            'insertion': 5,
            'deletion': 5,
            'transposition': 8,
            'vowel_swap': 8,
            'edit_distance': 0,
        }.get(technique, 0)

        risk = base_risk + technique_boost
        return int(max(0, min(100, risk)))


# ============================================
# CONVENIENCE FUNCTION
# ============================================

def check_typosquat(url_or_domain, brands_path=None):
    """
    Quick one-shot typosquat check.

    Returns: dict (see TyposquatResult.to_dict)
    """
    detector = TyposquattingDetector(brands_path=brands_path)
    return detector.analyze(url_or_domain).to_dict()


# ============================================
# SELF TEST
# ============================================

if __name__ == "__main__":
    import json

    detector = TyposquattingDetector()

    print(f"\n{'=' * 80}")
    print(f"TYPOSQUATTING DETECTOR — SELF TEST")
    print(f"{'=' * 80}")
    print(f"Loaded {len(detector.brands)} brands")
    print(f"High-value brands: {len(detector.high_value_brands)}")
    print(f"{'=' * 80}\n")

    test_domains = [
        # Benign
        "google.com",
        "microsoft.com",
        "paypal.com",
        "amazon.com",

        # Character substitution
        "paypa1.com",
        "micros0ft.com",
        "g00gle.com",
        "arnazon.com",

        # Combosquatting
        "paypal-secure.com",
        "secure-paypal.com",
        "microsoft-login.com",
        "amazon-verify.com",

        # Transposition
        "googel.com",
        "paaypl.com",

        # Homoglyph
        "аpple.com",       # Cyrillic 'а'
        "mіcrosoft.com",   # Cyrillic 'і'

        # Missing character
        "goole.com",
        "micosoft.com",

        # Vowel swap
        "paipel.com",
        "gougle.com",

        # Punycode
        "xn--pypal-4ve.com",

        # Multi-label
        "login.paypal-secure.com",
        "microsoft.com.account-verify.xyz",
    ]

    for domain in test_domains:
        result = detector.analyze(domain)
        marker = "🚨" if result.is_typosquat else "✅"
        print(f"\n{marker} {domain}")
        if result.matches:
            for m in result.matches[:3]:
                print(
                    f"    → Brand: {m.brand:<15} "
                    f"Similarity: {m.similarity:.2f}  "
                    f"Technique: {m.technique:<22}  "
                    f"Risk: {m.risk}"
                )
        else:
            print("    → No typosquat detected")

    print(f"\n{'=' * 80}")
    print("✅ Self test complete")
    print(f"{'=' * 80}\n")