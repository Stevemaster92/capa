import collections
import itertools
from typing import Dict

import capa.render.result_document as rd
import capa.features.freeze.features as frzf
import capa.render.utils as rutils
from capa.engine import MatchResults
from capa.rules import RuleSet
from capa.render.utils import StringIO
from capa.knowledge import ALL_ATTACK, ALL_MBC, VERDICTS

V_NONE = 0
V_MALICIOUS = 1
V_SUSPICIOUS = 2
V_TERMS = ["NONE", "MALICIOUS", "SUSPICIOUS"]

def find_subrule_matches(doc: rd.ResultDocument):
    """
    collect the rule names that have been matched as a subrule match.
    this way we can avoid displaying entries for things that are too specific.
    """
    matches = set([])

    def rec(match: rd.Match):
        if not match.success:
            # there's probably a bug here for rules that do `not: match: ...`
            # but we don't have any examples of this yet
            return

        elif isinstance(match.node, rd.StatementNode):
            for child in match.children:
                rec(child)

        elif isinstance(match.node, rd.FeatureNode) and isinstance(match.node.feature, frzf.MatchFeature):
            matches.add(match.node.feature.match)

    for rule in rutils.capability_rules(doc):
        for address, match in rule.matches:
            rec(match)

    return matches


def render_meta(doc: rd.ResultDocument, ostream: StringIO):
    cols = [
        doc.meta.sample.path,
        "OK",  # no error
        doc.meta.sample.md5,
        doc.meta.sample.sha1,
        doc.meta.sample.sha256,
        doc.meta.analysis.os,
        doc.meta.analysis.format,
        doc.meta.analysis.arch,
    ]

    ostream.write("\t".join(cols))
    ostream.write("\t")


def get_total_numbers(items: dict):
    """
    return the total number of keys and values per key in `items` as pair (n_keys, n_values).
    """
    # Count values of each key.
    total_values = 0
    for _, v in items.items():
        total_values += len(v)

    return (len(items), total_values)


def render_total_numbers(attack: dict, mbc: dict, capability: dict, ostream: StringIO):
    tactics, techniques = get_total_numbers(attack)
    objectives, behaviors = get_total_numbers(mbc)
    capabilities, namespaces = get_total_numbers(capability)

    cols = [
        str(tactics),
        str(techniques),
        str(objectives),
        str(behaviors),
        str(capabilities)
    ]

    ostream.write("\t".join(cols))
    ostream.write("\t")

def get_verdict(items: dict):
    """
    return the verdict determined from the entries in `items`.
    """
    verdict = V_NONE

    for key, values in items.items():
        for (_, _, id) in values:
            # Trim the ID if it contains a subtechnique. Otherwise, the following checks won't work.
            search = "%s::%s" % (key, str(id).split(".")[0])

            if search in VERDICTS["malicious"]:
                # Immediately return if a malicious ID is found.
                return V_MALICIOUS
            if search in VERDICTS["suspicious"]:
                # Store the SUSPICIOUS verdict which could be replaced by a malicious one later on.
                verdict = V_SUSPICIOUS

    # This either returns NONE or SUSPICIOUS.
    return verdict

def render_verdict(attack: dict, mbc: dict, ostream: StringIO):
    verdict = get_verdict(attack)

    # If verdict of ATT&CK is not already MALICIOUS, check verdict of MBC.
    if verdict != V_MALICIOUS:
        verdict_mbc = get_verdict(mbc)

        # Assign the new verdict only if it is MALICIOUS or SUSPICIOUS.
        if verdict_mbc != V_NONE:
            verdict = verdict_mbc

    ostream.write(V_TERMS[verdict])
    ostream.write("\t")

def get_items(doc: rd.ResultDocument, key: str):
    """
    extract items by type specified by `key`, e.g. capability, att&ck, mbc.
    """
    if key == "capability":
        subrule_matches = find_subrule_matches(doc)

    items = collections.defaultdict(set)

    for rule in rutils.capability_rules(doc):
        # Capabilities and namespaces
        if key == "capability":
            if rule.meta.name in subrule_matches:
                # rules that are also matched by other rules should not get rendered by default.
                # this cuts down on the amount of output while giving approx the same detail.
                # see #224
                continue

            items[rule.meta.name].add(rule.meta.namespace)
        else:
            # ATT&CK tactics and techniques
            if len(rule.meta.attack) > 0:
                for spec in rule.meta.attack:
                    items[spec.tactic].add((spec.technique, spec.subtechnique, spec.id))
            # MBC objectives and behaviors
            elif len(rule.meta.mbc) > 0:
                for spec in rule.meta.mbc:
                    items[spec.objective].add((spec.behavior, spec.method, spec.id))

    return items


def render_items(s_items: dict, all_items: Dict[str, Dict[str, str]], ostream: StringIO):
    """
    args:
        s_items (dict): the dictionary of capabilities belonging to the sample.
        all_items (dict): the dictionary of all the reference capabilities (e.g. ATT&CK or MBC).
        ostream (StringIO): the output stream to write the results to.
    example::

        key::root_val_1::child_val_1   key::root_val_1::child_val_2   [...]   key::root_val_2::child_val_1   key::root_val_2::child_val_2   [...]
        1   0   [...]   1   1   [...]
    """

    for key, values in all_items.items():
        s_values = s_items[key]

        for id, _ in values.items():
            search = "%s::%s" % (key, id)

            if search in VERDICTS["malicious"] or search in VERDICTS["suspicious"]:
                if s_values is None:
                    ostream.write(str(0))
                else:
                    found = False
                    for (_, _, s_id) in s_values:
                        if id in s_id:
                            found = True
                            break
                    ostream.write(str(1)) if found else ostream.write(str(0))
                ostream.write("\t")


def render_others(attack: dict, mbc: dict, ostream: StringIO):
    others = []

    for key, values in itertools.chain(attack.items(), mbc.items()):
        for (val, _, id) in values:
            # Trim the ID if it contains a subtechnique. Otherwise, the following checks won't work.
            search = "%s::%s" % (key, str(id).split(".")[0])

            # Add all entries which are neither malicious nor suspicious to the list.
            if search in VERDICTS["malicious"] or search in VERDICTS["suspicious"]:
                continue
            else:
                others.append("%s::%s::%s" % (key, val, id))

    ostream.write(str(len(others)))
    ostream.write("\t")
    ostream.write(", ".join(others))


def render_csv(doc: rd.ResultDocument):
    ostream = rutils.StringIO()

    s_attack = get_items(doc, "att&ck")
    s_mbc = get_items(doc, "mbc")
    s_capability = get_items(doc, "capability")

    render_meta(doc, ostream)
    render_total_numbers(s_attack, s_mbc, s_capability, ostream)
    render_verdict(s_attack, s_mbc, ostream)
    render_items(s_attack, ALL_ATTACK, ostream)
    render_items(s_mbc, ALL_MBC, ostream)
    render_others(s_attack, s_mbc, ostream)

    return ostream.getvalue()


def render_header():
    ostream = rutils.StringIO()

    cols = [
        "Path",
        "Error",
        "MD5",
        "SHA1",
        "SHA256",
        "OS",
        "Format",
        "Architecture",
        "ATT&CK Tactics",
        "ATT&CK Techniques",
        "MBC Objectives",
        "MBC Behaviors",
        "Capabilities",
        "Verdict"
    ]

    # Append headers for attacks and MBCs with a verdict.
    for key, values in itertools.chain(ALL_ATTACK.items(), ALL_MBC.items()):
        for id, val in values.items():
            search = "%s::%s" % (key, id)

            if search in VERDICTS["malicious"] or search in VERDICTS["suspicious"]:
                cols.append("%s::%s::%s" % (key, val, id))

    # Append headers for the summary of the remaining attacks and MBCs.
    cols.append("Others Sum")
    cols.append("Others")

    ostream.write("\t".join(cols))

    return ostream.getvalue()


def render_error(code: int, msg: str, path: str):
    ostream = rutils.StringIO()

    cols = [
        path,
        msg
    ]

    ostream.write("\t".join(cols))

    return ostream.getvalue()


def render(meta, rules: RuleSet, capabilities: MatchResults) -> str:
    doc = rd.ResultDocument.from_capa(meta, rules, capabilities)
    return render_csv(doc)
