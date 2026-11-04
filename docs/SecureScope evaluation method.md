# SecureScope evaluation method

Evaluate the inline origin rules separately from backend-assisted manual scans.
Freeze the dataset, detector hash and warning threshold before inspecting results.
Do not tune the detector on this sample and then describe it as a held-out test.

## Preliminary offline run

The runner `scripts/evaluate_inline.mjs` consumes JSON containing `metadata` and
`cases`. Each case needs a unique `id`, `url`, `label` (`phishing` or
`benign-assumed`) and `source`. Each origin may appear only once. Record feed
retrieval time, source snapshot hash, label provenance and sampling rule in the
metadata. Keep raw datasets and academic results local, outside project Git.

PhishTank's developer documentation describes a downloadable verified, online
phishing feed: https://phishtank.org/developer_info.php . A feed label applies to
the reported URL, not every page on its host. A curated set of legitimate
homepages is an assumed-benign convenience sample, not certified ground truth.
It underrepresents unusual legitimate domains, IDNs and shared hosting.

Run `node scripts/evaluate_inline.mjs DATASET.json OUTPUT.json`. The script only
parses URLs and calls the shipped local scorer. It never resolves or visits
sample hosts, uses no account, and sends no request to the shared API. It strips
paths, queries and fragments to reproduce the actual inline input. Predictions
contain IDs rather than clickable sample addresses.

Any Medium, High or Critical badge counts as a warning. Detection rate is warned
phishing cases / all phishing cases. False-warning rate is warned assumed-benign
cases / all assumed-benign cases. Unknown cases remain in class denominators as
non-warnings and are also counted separately. A Low result means no local rule
matched; neither Low nor Unknown establishes safety.

Each case has one warm-up and 21 timing repetitions; these repetitions are not
additional independent examples. The median records local classification time
only. It is not Chrome warning latency and cannot establish a three-second
end-to-end target. Hashes permit reproducibility without publishing source data.

## Remaining evaluation

A small pilot does not establish an 80% detection or 10% false-warning target.
The full study still needs a broader independently labelled set, a frozen
release, uncertainty estimates and separate Chrome warning-delay measurements.
Backend-assisted evaluation must record RDAP/reputation availability, cached
versus fresh evidence, failures and Unknown results. Reputation providers may
share intelligence with label sources, which can inflate apparent independence.
Do not run bulk requests against a teammate's live API or production accounts;
use an isolated test deployment and agreed provider quotas.
