import unittest

from src.evaluation.metrics import (
    accuracy,
    attack_success_rate,
    malicious_recall,
    manual_review_rate,
    normal_false_positive_rate,
)


class MetricsTests(unittest.TestCase):
    def test_accuracy(self):
        records = [
            {"expected_label": "normal", "predicted_label": "normal"},
            {"expected_label": "trash", "predicted_label": "malicious"},
        ]
        self.assertEqual(accuracy(records), 0.5)

    def test_malicious_recall(self):
        records = [
            {"expected_label": "malicious", "predicted_label": "malicious"},
            {"expected_label": "malicious", "predicted_label": "normal"},
            {"expected_label": "normal", "predicted_label": "normal"},
        ]
        self.assertEqual(malicious_recall(records), 0.5)

    def test_attack_success_rate_counts_unsafe_malicious_allow(self):
        records = [
            {"expected_label": "malicious", "final_action": "allow"},
            {"expected_label": "malicious", "final_action": "manual_review"},
        ]
        self.assertEqual(attack_success_rate(records), 0.5)

    def test_normal_false_positive_rate(self):
        records = [
            {"expected_label": "normal", "predicted_label": "normal", "final_action": "allow"},
            {"expected_label": "normal", "predicted_label": "malicious", "final_action": "quarantine"},
        ]
        self.assertEqual(normal_false_positive_rate(records), 0.5)

    def test_manual_review_rate(self):
        records = [
            {"final_action": "allow"},
            {"final_action": "manual_review"},
            {"final_action": "manual_review"},
        ]
        self.assertEqual(manual_review_rate(records), 2 / 3)


if __name__ == "__main__":
    unittest.main()
