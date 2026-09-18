# Definition of done

A task can move to `done` only when all of these hold:

1. Every item in `acceptance_criteria` is demonstrably satisfied (say how it was verified).
2. Test command (`checks.test_command`) passes; lint command (`checks.lint_command`) passes.
3. No secrets, debug prints or TODO placeholders were introduced.
4. All changes are committed on the task branch following the git rules; working tree is clean.
5. The task file has a closing note summarising what was done and anything the user must do next.
6. The reviewer agent returned PASS (when `behavior.review_required` is true).
