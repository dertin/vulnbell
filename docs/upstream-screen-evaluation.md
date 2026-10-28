# Evaluating upstream screening

Run the deterministic screen against independently labelled items before changing screening or
ordering rules:

```sh
vulnbell tools evaluate --from tests/fixtures/screening-evaluation.json --top 2
```

The fixture is deliberately small and synthetic. It includes a relevant stalled process described
without matching bug terms, which the screen does not select, so it demonstrates a false negative rather than
claiming production recall. Use a separate, independently reviewed and representative corpus for
actual decisions. Every input item needs a unique key, a relevance label and a rationale citing its
basis. Do not include private data in shared corpora.

The output reports selected count, precision, recall, false-negative keys, precision and recall at
the requested top K, and the select-all precision baseline. A zero denominator is null. Ranking
uses the same rules as the review packet but does not simulate advisory resolution or the
exact-affected tier. It does not measure correctness of imported decisions or exposure. A higher
score on one corpus does not establish general safety. The model only orders selected items and
does not dismiss findings. The current screen excludes items without its signals; inspect the
packet's bounded `unselected_sample`, and retain this coverage limitation.
