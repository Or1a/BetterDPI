"""Bounded, explainable heuristics; scores are not probabilities."""

KIB = 1024
MIB = 1024 * KIB
SCORING_REVISION = 5
FANOUT_WATCH_PEERS = 40
FANOUT_TIERS = ((80, 40), (FANOUT_WATCH_PEERS, 35), (20, 25))
DEFAULT_WEIGHTS = {'fanout': 25, 'serving_peers': 20, 'sustained': 20,
                   'upload_ratio': 15, 'domain': 20}
# Shared veto policy. Identity conflicts remain visible as incomplete journal
# evidence; explicit exemptions never enter simulated-block training samples.
PROTECTED_GUARDS = frozenset(('protected_transport', 'unsupported_proxy',
                              'shared_transport', 'allowlisted'))
REVOKING_GUARDS = PROTECTED_GUARDS | {'identity_changed'}


def score(metrics, domain_hint=False, weights=None):
    """Each correlated evidence family contributes at most its configured cap.

    This deliberately scores current windows, never accumulated event counts.
    Fanout has graduated ceilings, also capped by the configured weight. The
    default 25-point cap preserves existing scores; raising it rewards higher
    peer counts without giving ordinary 20-peer groups the entire new weight.
    A domain hint adds confidence but cannot by itself authorize an action.
    """
    weights = DEFAULT_WEIGHTS if weights is None else weights
    upload = metrics.get('upload', 0)
    download = metrics.get('download', 0)
    fanout = next((min(weights['fanout'], ceiling) for minimum, ceiling in FANOUT_TIERS
                   if metrics.get('peers', 0) >= minimum), 0)
    conditions = (
        ('fanout', metrics.get('peers', 0) >= 20),
        ('serving_peers', metrics.get('serving_peers', 0) >= 8),
        ('sustained', metrics.get('upload_minutes', 0) >= 3),
        ('upload_ratio', upload >= 4 * MIB and upload >= 3 * max(download, 1)),
        ('domain', domain_hint),
    )
    reasons = [{'id': name, 'points': fanout if name == 'fanout' else weights[name]}
               for name, matched in conditions if matched and weights[name] > 0]
    return min(100, sum(reason['points'] for reason in reasons)), reasons


def fast_score(weights, domain_hint=False, historical=False):
    """Only called after all independent kernel distribution gates pass.

    The same weight budgets and configured score threshold still apply. The
    fast route substitutes verified receiving-peer diversity and three growing
    counter observations for coarse fanout and whole-minute persistence.
    """
    families = [('historical_peers' if historical else 'upload_diversity', 'fanout'),
                ('historical_distribution' if historical else 'serving_peers', 'serving_peers'),
                ('active_distribution', 'sustained'), ('upload_ratio', 'upload_ratio')]
    if domain_hint:
        families.append(('domain', 'domain'))
    reasons = [dict(id=name, points=weights[family]) for name, family in families if weights[family]]
    return min(100, sum(reason['points'] for reason in reasons)), reasons
