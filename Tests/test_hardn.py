import unittest
import subprocess
import sys
import os

class TestHardN(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Install necessary packages using apt
        packages = ["python3-venv", "python3-pip"]
        subprocess.check_call(["sudo", "apt", "install", "-y"] + packages)
        subprocess.check_call(["sudo", "apt-get", "install", "-y"] + packages)

        # Create virtual environment
        subprocess.check_call([sys.executable, "-m", "venv", "env"])

        # Activate the virtual environment and install requirements
        subprocess.check_call(["env/bin/pip", "install", "-r", "requirements.txt"])

        # Run setup.sh
        subprocess.check_call(["/bin/bash", "setup.sh"])

    def test_example(self):
        # Call hardn.py from the Src folder
        result = subprocess.run([sys.executable, "Src/hardn.py"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

if __name__ == '__main__':
    unittest.main()