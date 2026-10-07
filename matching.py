"""
Secret Santa assignment.

Fills every open "needs a santa" slot among active, eligible users such that:
  * everyone receives exactly one gift, and gives one (two only if their max_match_count allows it)
  * shipping rules hold (same country, EU -> EU member, or santa ships internationally)
  * pairings from prior years are avoided whenever a repeat-free assignment exists
  * the giving order forms as few, as long cycles as possible, so your santa is rarely also your recipient

Existing active matches are never touched; running it again only fills gaps (that is how the "+1" button works).
"""
import random
from collections import defaultdict

from models import User, Match, EU, EU_COUNTRIES

COST_PRIOR_REVERSE = 1  # they gave to you in a prior year
COST_PRIOR_SAME = 10  # you gave to them in a prior year
RESTARTS = 25


def can_ship(santa: User, recipient: User) -> bool:
    if santa.id == recipient.id:
        return False
    return bool(santa.ship_internationally or santa.country == recipient.country
                or (santa.country == EU and recipient.country in EU_COUNTRIES))


def prior_pairs():
    """(santa_id, recipient_id) for every archived match."""
    archived = Match.select(Match.secret_santa, Match.match).where(Match.is_active == False)
    return {(m.secret_santa_id, m.match_id) for m in archived}


def pair_cost(santa: User, recipient: User, prior) -> int:
    if (santa.id, recipient.id) in prior:
        return COST_PRIOR_SAME
    if (recipient.id, santa.id) in prior:
        return COST_PRIOR_REVERSE
    return 0


class Assignment:
    """One candidate solution: edges[i] = list of recipient indexes for santa i."""

    def __init__(self, users, allowed, cost, capacity, needs_santa, rng):
        self.users = users
        self.allowed = allowed  # allowed[i] = set of j that santa i may give to
        self.cost = cost  # cost[i][j]
        self.capacity = capacity  # how many *new* recipients santa i may take
        self.needs_santa = needs_santa  # set of recipient indexes without an active santa
        self.rng = rng
        self.santa_of = {}  # recipient j -> santa i (new edges only)
        self.recips_of = defaultdict(list)  # santa i -> [j, ...]

    # ---- phase 1: max bipartite matching, cheapest edges first --------------------------------

    def solve(self):
        n = len(self.users)
        # Stage in the costlier edges only when the cheaper ones cannot match everyone,
        # and only open second gift slots when a santa's first slot is not enough.
        stages = [(0, 1), (COST_PRIOR_REVERSE, 1), (COST_PRIOR_SAME, 1), (COST_PRIOR_SAME, None)]
        self.slot_of = {}  # recipient j -> (i, k); kept across stages
        for max_cost, max_slots in stages:
            slots = [(i, k) for i in range(n) for k in range(self.capacity[i])
                     if max_slots is None or k < max_slots]
            self.rng.shuffle(slots)
            for slot in slots:
                if slot not in self.slot_of.values():
                    self._augment(slot, max_cost, set())
            if len(self.slot_of) == len(self.needs_santa):
                break
        self._rebuild_from_slots()

    def _augment(self, slot, max_cost, seen):
        i, _ = slot
        candidates = [j for j in self.allowed[i] if j in self.needs_santa and self.cost[i][j] <= max_cost]
        self.rng.shuffle(candidates)
        for j in candidates:
            if j in seen:
                continue
            seen.add(j)
            if j not in self.slot_of or self._augment(self.slot_of[j], max_cost, seen):
                self.slot_of[j] = slot
                return True
        return False

    def _rebuild_from_slots(self):
        self.santa_of = {}
        self.recips_of = defaultdict(list)
        for j, (i, _) in sorted(self.slot_of.items(), key=lambda kv: kv[1]):
            self.santa_of[j] = i
            self.recips_of[i].append(j)

    # ---- phase 2: merge small cycles into big ones -----------------------------------------------

    def primary(self):
        """Each santa's first recipient; the chain of these forms cycles and paths."""
        return {i: js[0] for i, js in self.recips_of.items() if js}

    def components(self):
        nxt = self.primary()
        has_primary_santa = set(nxt.values())
        seen = set()
        comps = []
        # paths start at a node nobody (primarily) gives to
        for start in list(nxt):
            if start in has_primary_santa:
                continue
            path, node = [], start
            while node is not None and node not in seen:
                seen.add(node)
                path.append(node)
                node = nxt.get(node)
            comps.append((path, False))
        # everything left is on a cycle
        for start in nxt:
            if start in seen:
                continue
            cyc, node = [], start
            while node not in seen:
                seen.add(node)
                cyc.append(node)
                node = nxt[node]
            comps.append((cyc, True))
        return comps

    @staticmethod
    def _edges(comp):
        nodes, is_cycle = comp
        edges = list(zip(nodes, nodes[1:]))
        if is_cycle:
            edges.append((nodes[-1], nodes[0]))
        return edges

    def _swap(self, a, b, c, d):
        """Replace a->b, c->d with a->d, c->b."""
        self.recips_of[a][self.recips_of[a].index(b)] = d
        self.recips_of[c][self.recips_of[c].index(d)] = b
        self.santa_of[d], self.santa_of[b] = a, c

    def _try_merge(self, x, y):
        for a, b in self._edges(x):
            for c, d in self._edges(y):
                if d in self.allowed[a] and b in self.allowed[c] and \
                        self.cost[a][d] + self.cost[c][b] <= self.cost[a][b] + self.cost[c][d]:
                    self._swap(a, b, c, d)
                    return True
        return False

    def merge_cycles(self):
        while True:
            comps = self.components()
            cycles = [c for c in comps if c[1]]
            if len(cycles) < 2 and not any(len(c[0]) == 2 for c in cycles):
                return
            # shortest cycles first: a 2-cycle is what we most want to get rid of
            cycles.sort(key=lambda c: len(c[0]))
            merged = False
            for x in cycles:
                others = [c for c in comps if c is not x and (c[1] or len(x[0]) == 2)]
                for y in others:
                    if self._try_merge(x, y):
                        merged = True
                        break
                if merged:
                    break
            if not merged:
                return

    # ---- scoring ----------------------------------------------------------------------------------

    def score(self):
        comps = self.components()
        total_cost = sum(self.cost[i][j] for i, js in self.recips_of.items() for j in js)
        two_cycles = sum(1 for nodes, is_cycle in comps if is_cycle and len(nodes) == 2)
        extra_gifts = sum(max(0, len(js) - 1) for js in self.recips_of.values())
        unmatched = len(self.needs_santa) - len(self.santa_of)
        return unmatched, extra_gifts, total_cost, two_cycles, len(comps)

    def edges(self):
        return [(self.users[i], self.users[j]) for i, js in self.recips_of.items() for j in js]


def plan_matches(users, prior, restarts=RESTARTS, seed=None):
    """Pick the best assignment over several randomized attempts. Returns an Assignment (or None)."""
    users = list(users)
    if not users:
        return None
    rng = random.Random(seed)
    n = len(users)
    allowed = [{j for j in range(n) if can_ship(users[i], users[j])} for i in range(n)]
    cost = [[pair_cost(users[i], users[j], prior) if j in allowed[i] else 0 for j in range(n)] for i in range(n)]
    capacity = [max(0, u.max_match_count - u.n_recipients) for u in users]
    needs_santa = {j for j, u in enumerate(users) if u.secret_santa is None}

    best = None
    for _ in range(restarts):
        a = Assignment(users, allowed, cost, capacity, needs_santa, rng)
        a.solve()
        a.merge_cycles()
        if best is None or a.score() < best.score():
            best = a
    return best


def eligible_users():
    return [u for u in User.select().where(User.active_this_year == True) if u.eligible_for_participation()]


def match_users(seed=None):
    """Create Match rows for everyone who still needs a santa. Returns the Assignment used, or None."""
    plan = plan_matches(eligible_users(), prior_pairs(), seed=seed)
    if plan is None:
        return None
    for santa, recipient in plan.edges():
        Match.create(secret_santa=santa, match=recipient)
    return plan


def summarize(plan) -> str:
    if plan is None:
        return "Nobody to match."
    unmatched, extra_gifts, total_cost, two_cycles, n_components = plan.score()
    repeats = sum(1 for i, js in plan.recips_of.items() for j in js if plan.cost[i][j] >= COST_PRIOR_SAME)
    reverse = sum(1 for i, js in plan.recips_of.items() for j in js if plan.cost[i][j] == COST_PRIOR_REVERSE)
    return (f"Matched {len(plan.santa_of)} of {len(plan.needs_santa)} people who needed a santa. "
            f"{unmatched} left without one. {extra_gifts} santas giving an extra gift. "
            f"Repeat pairings from a prior year: {repeats} (plus {reverse} where the roles are swapped). "
            f"Gift circles: {n_components}, of which {two_cycles} are just two people swapping.")
