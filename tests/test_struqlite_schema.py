import unittest

from src.struqlite.schema import response_format_json_schema, validate_model_response


class SchemaValidationTests(unittest.TestCase):
    def test_valid_response_routes_by_label(self):
        result = validate_model_response(
            '{"label":"malicious","confidence":0.92,"reason":"phishing","indicators":["credential request"],"recommended_action":"quarantine"}'
        )
        self.assertEqual(result.validation_status, "valid")
        self.assertEqual(result.final_action, "quarantine")

    def test_invalid_json_falls_back(self):
        result = validate_model_response("not json")
        self.assertEqual(result.validation_status, "fallback")
        self.assertEqual(result.final_action, "manual_review")

    def test_truncated_final_brace_is_repaired(self):
        result = validate_model_response(
            '{"label":"normal","confidence":0.9,"reason":"normal subject and body text","indicators":["normal subject"],"recommended_action":"allow"'
        )
        self.assertEqual(result.validation_status, "valid")
        self.assertEqual(result.final_action, "allow")

    def test_truncated_json_inside_text_is_repaired(self):
        result = validate_model_response(
            'Here is the JSON:\n{"label":"trash","confidence":0.88,"reason":"newsletter","indicators":[],"recommended_action":"archive"'
        )
        self.assertEqual(result.validation_status, "valid")
        self.assertEqual(result.final_action, "archive")

    def test_unknown_label_falls_back(self):
        result = validate_model_response(
            '{"label":"safe","confidence":0.99,"reason":"x","indicators":[],"recommended_action":"allow"}'
        )
        self.assertEqual(result.validation_status, "fallback")
        self.assertIn("unknown label", result.validation_errors[0])

    def test_low_confidence_falls_back(self):
        result = validate_model_response(
            '{"label":"normal","confidence":0.2,"reason":"x","indicators":[],"recommended_action":"allow"}'
        )
        self.assertEqual(result.final_action, "manual_review")

    def test_response_format_uses_strict_json_schema(self):
        response_format = response_format_json_schema()
        self.assertEqual(response_format["type"], "json_schema")
        self.assertTrue(response_format["json_schema"]["strict"])


if __name__ == "__main__":
    unittest.main()
