import collections
import itertools
from typing import Dict

import capa.render.result_document
import capa.render.utils as rutils
from capa.engine import MatchResults
from capa.rules import RuleSet
from capa.render.utils import StringIO
from capa.knowledge import ALL_ATTACK, ALL_MBC, VERDICTS


def find_subrule_matches(doc):
    """
    collect the rule names that have been matched as a subrule match.
    this way we can avoid displaying entries for things that are too specific.
    """
    matches = set([])

    def rec(node):
        if not node["success"]:
            # there's probably a bug here for rules that do `not: match: ...`
            # but we don't have any examples of this yet
            return

        elif node["node"]["type"] == "statement":
            for child in node["children"]:
                rec(child)

        elif node["node"]["type"] == "feature":
            if node["node"]["feature"]["type"] == "match":
                matches.add(node["node"]["feature"]["match"])

    for rule in rutils.capability_rules(doc):
        for node in rule["matches"].values():
            rec(node)

    return matches


def render_meta(doc, ostream: StringIO):
    cols = [
        doc["meta"]["sample"]["path"],
        "OK",  # no error
        # doc["meta"]["sample"]["md5"],
        # doc["meta"]["sample"]["sha1"],
        doc["meta"]["sample"]["sha256"],
        doc["meta"]["analysis"]["os"],
        doc["meta"]["analysis"]["format"],
        # doc["meta"]["analysis"]["arch"],
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
    verdict = ""

    for key, values in items.items():
        for (_, _, id) in values:
            search = "%s::%s" % (key, id)

            if search in VERDICTS["malicious"]:
                # Immediately return if a malicious ID is found.
                return "MALICIOUS"
            if search in VERDICTS["suspicious"]:
                # Store a SUSPICIOUS verdict which could be replaced by a malicious one.
                verdict = "SUSPICIOUS"

    # This either returns an empty or SUSPICIOUS verdict.
    return verdict

def render_verdict(attack: dict, mbc: dict, ostream: StringIO):
    verdict = get_verdict(attack)

    if verdict == "":
        verdict = get_verdict(mbc)

    ostream.write(verdict)
    ostream.write("\t")

def get_items(doc, key: str):
    """
    extract items by type specified by `key`, e.g. capability, att&ck, mbc.
    """
    if key == "capability":
        subrule_matches = find_subrule_matches(doc)

    items = collections.defaultdict(set)

    for rule in rutils.capability_rules(doc):
        # Capabilities and namespaces
        if key == "capability":
            if rule["meta"]["name"] in subrule_matches:
                # rules that are also matched by other rules should not get rendered by default.
                # this cuts down on the amount of output while giving approx the same detail.
                # see #224
                continue

            items[rule["meta"]["name"]].add(rule["meta"]["namespace"])
        else:
            if not rule["meta"].get(key):
                continue

            for val in rule["meta"][key]:
                if key == "att&ck":
                    # ATT&CK tactics and techniques
                    items[val["tactic"]].add((val["technique"], val.get("subtechnique"), val["id"]))
                elif key == "mbc":
                    # MBC objectives and behaviors
                    items[val["objective"]].add((val["behavior"], val.get("method"), val["id"]))

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


def render_csv(doc):
    ostream = rutils.StringIO()

    s_attack = get_items(doc, "att&ck")
    s_mbc = get_items(doc, "mbc")
    s_capability = get_items(doc, "capability")

    render_meta(doc, ostream)
    render_total_numbers(s_attack, s_mbc, s_capability, ostream)
    render_verdict(s_attack, s_mbc, ostream)
    render_items(s_attack, ALL_ATTACK, ostream)
    render_items(s_mbc, ALL_MBC, ostream)

    return ostream.getvalue()


def render_header():
    ostream = rutils.StringIO()

    cols = [
        "Path",
        "Error",
        # "MD5",
        # "SHA1",
        "SHA256",
        "OS",
        "Format",
        # "Architecture",
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
    doc = capa.render.result_document.convert_capabilities_to_result_document(meta, rules, capabilities)
    return render_csv(doc)
