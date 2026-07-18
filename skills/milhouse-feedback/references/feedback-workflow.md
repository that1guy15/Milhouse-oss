# Feedback Workflow Reference

Feedback item statuses:

- `open`: evidence exists and no owner/action has been accepted.
- `accepted`: an agent or human accepted the item.
- `shipped`: a change landed and is waiting for signal verification.
- `verified`: the signal improved.
- `regressed`: the signal did not improve or worsened.
- `rejected`: the item was intentionally declined with rationale.

Evidence to include when updating status:

- PR or commit
- test result
- deploy/run id
- relevant event query
- remaining risk

Do not call work verified based only on agent confidence.
