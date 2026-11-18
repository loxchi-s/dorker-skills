import unittest

from token_budget import calculate_token_budget, estimate_tokens_upper_bound


class TokenBudgetTests(unittest.TestCase):
    def test_input_budget_never_exceeds_ninety_percent_or_output_reserve(self):
        budget = calculate_token_budget(
            system_prompt="system",
            user_prompt="review",
            context_window=4096,
            output_reserve=768,
            framing_overhead=128,
        )
        self.assertLessEqual(budget.input_limit, int(4096 * 0.90))
        self.assertLessEqual(budget.input_limit + budget.output_reserve, 4096)
        self.assertLessEqual(
            budget.fixed_prompt_tokens + budget.diff_token_budget,
            budget.input_limit,
        )

    def test_utf8_estimator_counts_bytes_not_code_points(self):
        self.assertEqual(3, estimate_tokens_upper_bound("界"))

    def test_prompt_larger_than_budget_fails_closed(self):
        with self.assertRaises(ValueError):
            calculate_token_budget(
                system_prompt="x" * 4000,
                user_prompt="",
                context_window=4096,
                output_reserve=768,
            )

    def test_invalid_budget_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            calculate_token_budget(
                system_prompt="s",
                user_prompt="u",
                context_window=4096,
                output_reserve=4096,
            )


if __name__ == "__main__":
    unittest.main()
