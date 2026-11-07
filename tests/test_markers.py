"""Compare accelerated marker discovery with the original exhaustive byte searches."""

import random
import unittest
from unittest.mock import patch

from nup_shader_audit.markers import MarkerFinder, PATTERNS, python_markers


def offsets(found):
    return {pattern: list(matches) for pattern, matches in found.items()}


class MarkerTests(unittest.TestCase):
    def test_unwritable_optional_cache_keeps_scanning(self):
        with patch('nup_shader_audit.markers.build_finder', side_effect=PermissionError('read-only cache')):
            finder = MarkerFinder()
        data = bytes(4096) + PATTERNS[0] + PATTERNS[2]
        self.assertIsNone(finder.function)
        self.assertEqual(offsets(finder.find(data)), offsets(python_markers(data)))

    def test_fallback_and_short_inputs(self):
        finder = MarkerFinder(native=False)
        for size in range(33):
            for pattern in PATTERNS:
                data = b'!' * size + pattern + b'!'
                self.assertEqual(offsets(finder.find(data)), offsets(python_markers(data)))
        self.assertEqual(offsets(finder.find(b'')), offsets(python_markers(b'')))

    def test_native_boundaries_random_bytes_and_overflow(self):
        finder = MarkerFinder()
        if finder.function is None:
            self.skipTest('Optional Windows x64 marker helper requires MSVC')
        rng = random.Random(703)
        for tail in range(33):
            data = bytearray(rng.randbytes(4096 + tail))
            for i, pattern in enumerate(PATTERNS):
                at = 128 * i + tail
                data[at:at + len(pattern)] = pattern
            # Exercise the scalar tail and matches crossing the last vector boundary.
            pattern = PATTERNS[tail % len(PATTERNS)]
            data[-len(pattern):] = pattern
            raw = bytes(data)
            self.assertEqual(offsets(finder.find(raw)), offsets(python_markers(raw)))
        for size in range(1024, 1056):
            self.assertEqual(offsets(finder.find(bytes(size))), offsets(python_markers(bytes(size))))
        bounded = MarkerFinder(capacity=2)
        crowded = PATTERNS[2] * 1024
        self.assertEqual(offsets(bounded.find(crowded)), offsets(python_markers(crowded)))


if __name__ == '__main__':
    unittest.main()
