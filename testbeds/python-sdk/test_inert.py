"""The Python SDK under plain Python: every site inert, nothing reaching a
shim, the program's own behaviour unchanged."""

import unittest

import patina


class Inert(unittest.TestCase):
    def test_no_shim_and_not_simulated(self):
        self.assertIsNone(patina._patina)
        self.assertFalse(patina.is_simulated())

    def test_checks_return_their_condition(self):
        always = patina.Always("inert-always")
        self.assertFalse(always.check(False, "detail"))
        self.assertTrue(always.check(1))
        self.assertTrue(patina.Sometimes("inert-sometimes").check(True))
        patina.Reachable("inert-reachable").mark()

    def test_faults_never_fire_and_knobs_keep_their_default(self):
        self.assertFalse(patina.Buggify("inert-fault").fires())
        self.assertFalse(patina.Buggify("inert-fault-p").fires(1.0))
        self.assertFalse(patina.BuggifyDelay("inert-delay").delay())
        self.assertEqual(patina.Knob("inert-knob", 8, 4, 16).value(), 8)

    def test_a_site_names_its_declaration(self):
        site = patina.Always("inert-where")
        self.assertTrue(site.where.endswith(f"test_inert.py:{_line_of('inert-where')}"))

    def test_a_label_must_be_a_nonempty_str(self):
        for label in ("", None, b"bytes", "lone-\udcff"):
            with self.assertRaises(ValueError):
                patina.Always(label)

    def test_run_markers_and_parameters_are_absent(self):
        patina.setup_complete()
        patina.lifecycle_event("inert")
        patina.verdict(patina.Verdict.PASS, "inert", "{}")
        self.assertIsNone(patina.param("anything"))

    def test_rng_draws_64_bit_values(self):
        draws = [patina.rng() for _ in range(4)]
        self.assertTrue(all(0 <= draw < 1 << 64 for draw in draws))
        self.assertEqual(len(set(draws)), 4)


def _line_of(label):
    with open(__file__) as source:
        return next(n for n, line in enumerate(source, 1) if f'"{label}"' in line)


if __name__ == "__main__":
    unittest.main()
