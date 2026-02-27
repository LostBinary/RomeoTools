import unittest
import importlib.util
import sys
from pathlib import Path

# Cargar módulo RomeoTools desde el archivo fuente
mod_path = Path(__file__).resolve().parents[1] / 'RomeoTools' / 'RomeoTools.py'
spec = importlib.util.spec_from_file_location('rometools_module', str(mod_path))
rt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rt)

class TestRomeoToolsSafeMode(unittest.TestCase):
    def test_run_cmd_simulation(self):
        rt.SAFE_MODE = True
        rc, out, err = rt.run_cmd(['echo','hello'])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_ping_simulation(self):
        rt.SAFE_MODE = True
        ok = rt.ping_host('127.0.0.1')
        self.assertFalse(ok)


if __name__ == '__main__':
    unittest.main()
