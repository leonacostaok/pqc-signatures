"""Acceptance regression checks for the ten-key sensitivity experiment."""
import copy
import unittest
import run


class Acceptance(unittest.TestCase):
    def setUp(self):
        self.expected = [('P', 0), ('P', 1)]
        self.rows = [dict(parameter=p, key=k, valid=True, tamper_rejected=True,
                          rng_keygen_bytes=48, rng_sign_bytes=16,
                          keygen_wall_ns=10, keygen_cpu_ns=10,
                          sign_wall_ns=20, sign_cpu_ns=20,
                          verify_wall_ns=30, verify_cpu_ns=30)
                     for p, k in self.expected]

    def test_complete(self):
        run.check_records(self.rows, self.expected, {'P': 16})

    def test_empty_duplicate_wrong_identity_and_failed_verdict(self):
        bad = [[], [self.rows[0], self.rows[0]], self.rows[:1]]
        for field, value in [('parameter', 'OTHER'), ('valid', False),
                             ('tamper_rejected', False), ('rng_sign_bytes', 15),
                             ('rng_keygen_bytes', 47), ('keygen_wall_ns', 0),
                             ('sign_cpu_ns', float('nan')), ('verify_cpu_ns', -1)]:
            rows = copy.deepcopy(self.rows); rows[0][field] = value; bad.append(rows)
        for rows in bad:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                run.check_records(rows, self.expected, {'P': 16})


if __name__ == '__main__':
    unittest.main()
