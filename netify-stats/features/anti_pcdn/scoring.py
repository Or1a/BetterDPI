"""Bounded, explainable heuristics; scores are not probabilities."""

KIB = 1024
MIB = 1024 * KIB
DEFAULT_WEIGHTS = {'fanout': 25, 'serving_peers': 20, 'sustained': 20,
                   'upload_ratio': 15, 'domain': 20}


def score(metrics, domain_hint=False, weights=None):
    """Each correlated evidence family contributes at most its configured cap.

    This deliberately scores current windows, never accumulated event counts.
    The default four behavior families can reach the inclusive threshold 80;
    a domain hint adds confidence but cannot by itself authorize an action.
    """
    weights = DEFAULT_WEIGHTS if weights is None else weights
    upload = metrics.get('upload', 0)
    download = metrics.get('download', 0)
    conditions = (
        ('fanout', metrics.get('peers', 0) >= 20),
        ('serving_peers', metrics.get('serving_peers', 0) >= 8),
        ('sustained', metrics.get('upload_minutes', 0) >= 3),
        ('upload_ratio', upload >= 4 * MIB and upload >= 3 * max(download, 1)),
        ('domain', domain_hint),
    )
    reasons = [{'id': name, 'points': weights[name]}
               for name, matched in conditions if matched and weights[name] > 0]
    return min(100, sum(reason['points'] for reason in reasons)), reasons
