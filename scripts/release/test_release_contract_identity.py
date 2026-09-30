"""The release-intent contract is bound to the repository's current name and stable id."""
import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
CONTRACT = SCRIPTS.parent / ".codestra" / "production-orchestrator-contract.v1.json"


def load_validator():
    spec = importlib.util.spec_from_file_location("keycloak_validate_workflows", SCRIPTS / "validate-workflows.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ReleaseContractIdentityTests(unittest.TestCase):
    validator = load_validator()

    def check(self, contract):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            original = self.validator.RELEASE_CONTRACT
            self.validator.RELEASE_CONTRACT = path
            try:
                self.validator.validate_release_contract()
            finally:
                self.validator.RELEASE_CONTRACT = original

    def test_checked_in_contract_names_the_transferred_repository(self):
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual((contract["repository"], contract["repository_id"]), ("appolon1908/Keycloak", 1347523366))
        self.check(contract)

    def test_previous_owner_other_name_or_other_id_is_rejected(self):
        base = json.loads(CONTRACT.read_text(encoding="utf-8"))
        for field, value in [("repository", "appolon1908-hue/Keycloak"), ("repository", "ingtrader21-spec/Keycloak"),
                             ("repository", "appolon1908/Keycloak-fork"), ("repository_id", 1347523367),
                             ("repository_id", "1347523366")]:
            contract = copy.deepcopy(base)
            contract[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(self.validator.PolicyError):
                    self.check(contract)


if __name__ == "__main__":
    unittest.main()
