#!/usr/bin/env python3
"""
Linux Guardian -- test_nlp.py                          (Phase 6 refinement)

PROOF FOR THE SPELLING-TOLERANT MATCHING LAYERS.

Run it live:   python3 test_nlp.py
Exit code is the number of failures, so it can gate a build.

The console resolves a sentence in four attempts, and a lower-numbered one
always wins:

    1  exact keyword match       ceiling 0.97   (guardian_nlp.match)
    2  normalised match          ceiling 0.95   (guardian_nlp.match_normalized)
    3  fuzzy match               ceiling 0.93   (guardian_nlp.match_fuzzy)
    4  Ollama                    >= 0.75        (guardian_ollama)

THIS FILE COVERS LAYERS 2 AND 3, which are the ones that have been built. It is
deliberately possible to run it with the model stopped, uninstalled, or never
heard of: nothing below opens a socket.

WHY THE ASSERTIONS ARE ABOUT WHICH LAYER FIRED, not merely about the final
answer. "check the disk" resolving to check_disk proves nothing on its own --
it would pass even if every layer had been wired in the wrong order. The
ordering rule is the safety property here, so the tests name the layer.
"""

import guardian_actions as ga
import guardian_nlp as nlp

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
failures = 0


def head(title):
    print(f"\n\033[1m{title}\033[0m")
    print("-" * 78)


def record(ok):
    global failures
    if not ok:
        failures += 1
    return PASS if ok else FAIL


def check(ok, label):
    print(f"  {record(ok)}  {label}")


# ===========================================================================
head("1 -- normalize(): lower-case, punctuation, fillers, synonyms")

# Each row is (input, expected output). The expected strings are written out
# in full rather than computed, so this table is readable in the report and
# cannot pass by accidentally agreeing with a bug in the code under test.
CASES = [
    # lower-casing and whitespace collapse
    ("How MUCH RAM is left?",        "memory left"),
    ("   disk     usage   ",         "disk usage"),
    ("\tcheck\ndisk\t",              "check disk"),

    # punctuation becomes a word boundary, never a deletion
    ("cpu,disk",                     "cpu disk"),
    ("!!!",                          ""),
    ("",                             ""),

    # digits and ':' survive -- a time must come through intact for step 3
    ("every thursday at 12:00",      "every thursday 12:00"),
    ("at 9pm",                       "9pm"),

    # '_' and '-' survive, because both are legal in a Guardian file name and
    # layer 1 keeps them too
    ("create a file called my-notes", "create file called my-notes"),
    ("file named my_notes",           "file named my_notes"),

    # the synonym table
    ("whats my hdd at",              "disk"),
    ("check my ssd",                 "check disk"),
    ("how much storage",             "disk"),
    ("free space",                   "free disk"),
    ("the mem",                      "memory"),
    ("processor load",               "cpu load"),
    ("is the internet up",           "network up"),
    ("wifi ok",                      "network ok"),
    ("restart the httpd daemon",     "restart apache2 service"),
    ("is apache running",            "apache2 running"),

    # plural forms of a synonym key
    ("check the daemons",            "check service"),
    ("my ssds",                      "disk"),

    # a plural whose singular is NOT in the table is left completely alone
    ("the processes",                "processes"),
]

for text, expected in CASES:
    got = nlp.normalize(text)
    check(got == expected, f"normalize({text!r:<34}) -> {got!r:<30} "
                           f"{'' if got == expected else 'EXPECTED ' + repr(expected)}")

# normalize() never returns None and never raises, whatever it is handed.
for hostile in ["../../etc/passwd", "'; rm -rf /", "\x00\x01", "a" * 5000]:
    got = nlp.normalize(hostile)
    check(isinstance(got, str), f"normalize() returns a string for {hostile[:18]!r}")


# ===========================================================================
head("2 -- the tables cannot contradict themselves")

# NO SYNONYM'S VALUE IS ANOTHER SYNONYM'S KEY. If one were, normalisation
# would depend on how many passes it made -- 'a' -> 'b' -> 'c' is a chain, and
# a single-pass function would stop halfway. Forbidding chains is what makes
# one pass provably enough.
chains = {k: v for k, v in nlp.SYNONYMS.items() if v in nlp.SYNONYMS}
check(not chains, f"no synonym maps onto another synonym's key {chains or ''}")

# A synonym whose canonical term is a filler would delete meaning: the word
# would be translated and then thrown away, and the action it pointed at would
# become unreachable.
swallowed = {k: v for k, v in nlp.SYNONYMS.items() if v in nlp.FILLERS}
check(not swallowed, f"no synonym resolves to a filler word {swallowed or ''}")

# LAYER 2 STRIPS EVERYTHING LAYER 1 STRIPS, AND MORE. A word layer 1 has
# already judged meaningless cannot become meaningful one layer later, so
# FILLERS must be a superset of STOPWORDS. Asserting the relation is what
# stops the two tables drifting apart when somebody extends one of them.
check(nlp.STOPWORDS <= nlp.FILLERS,
      f"FILLERS is a superset of STOPWORDS "
      f"(+{len(nlp.FILLERS - nlp.STOPWORDS)} words: "
      f"{sorted(nlp.FILLERS - nlp.STOPWORDS)})")

# IDEMPOTENCE: normalising twice is the same as normalising once. The trigger
# table is normalised at import and the user's sentence at request time; if the
# function were not idempotent, a phrase that had already been through it could
# come out different from one that had not.
not_idempotent = [t for t, _ in CASES if nlp.normalize(nlp.normalize(t)) != nlp.normalize(t)]
check(not not_idempotent, f"normalize() is idempotent {not_idempotent or ''}")

# EVERY ACTION IS STILL REACHABLE AT LAYER 2. A trigger phrase made entirely of
# filler words would normalise to nothing and be dropped, leaving an action
# that layer 2 could never return -- a hole nobody would notice until a demo.
empty = [a for a, phrases in nlp.NORMALIZED_TRIGGERS.items() if not phrases]
check(not empty, f"every action keeps at least one normalised trigger {empty or ''}")

check(set(nlp.NORMALIZED_TRIGGERS) == set(nlp.TRIGGERS),
      "the normalised table covers exactly the same actions as TRIGGERS")

check(set(nlp.TRIGGERS) == set(ga.action_ids()),
      "and exactly the actions the registry declares")

# No normalised phrase repeats a word. 'disk space' -> 'disk disk' would score
# one occurrence of 'disk' as two words matched and inflate that action's
# evidence over a rival that really did match two different words.
repeats = {a: p for a, phrases in nlp.NORMALIZED_TRIGGERS.items()
           for p in phrases if len(p.split()) != len(set(p.split()))}
check(not repeats, f"no normalised phrase repeats a word {repeats or ''}")


# ===========================================================================
head("3 -- layer 2 answers what layer 1 could not")

# Every sentence here is one a person would plausibly type, that the literal
# dictionary has NO opinion on, and that becomes obvious once the synonym table
# has spoken. This is the whole justification for the layer: none of these need
# a language model, and none of them are misspelled.
LAYER2 = {
    "whats my hdd at":      "check_disk",
    "check the ssd":        "check_disk",
    "how much space":       "check_disk",
    "check my ssd space":   "check_disk",
    "the mem":              "check_memory",
    "how much mem is free": "check_memory",
    "wifi ok":              "check_network",
    "net status":           "check_network",
    "check the daemons":    "check_service",
}

for sentence, expected in LAYER2.items():
    layer1 = nlp.match(sentence)
    layer2 = nlp.match_normalized(sentence)
    got = layer2[0].action_id if layer2 else None
    ok = (layer1 == [] and got == expected
          and layer2[0].source == "normalized"
          and layer2[0].confidence >= nlp.min_confidence())
    print(f"  {record(ok)}  {sentence!r:<24} -> {nlp.normalize(sentence)!r:<22} "
          f"-> {got} ({layer2[0].confidence if layer2 else '-'})"
          f"{'' if layer1 == [] else '  BUT LAYER 1 ALSO MATCHED'}")

# THE CEILING. A normalised reading may never report itself as more certain
# than a literal one. The same sentence scores 0.96 at layer 1 and is held at
# 0.95 here -- not because the reading is worse, but because a translated match
# must never outrank an exact one on confidence alone.
sentence = "create a file called notes containing hello"
exact = nlp.match(sentence)[0]
normalised = nlp.match_normalized(sentence)[0]
check(exact.confidence > normalised.confidence and normalised.confidence <= 0.95,
      f"layer 2 is capped below layer 1 ({exact.confidence} exact vs "
      f"{normalised.confidence} normalised)")

# THE AMBIGUITY RULE STILL APPLIES AT LAYER 2. Normalising 'what running' and
# 'running' both to 'running' makes list_processes and check_service genuinely
# indistinguishable, and the honest answer is to ask rather than to pick.
ambiguous = nlp.match_normalized("whats running")
ids = [c.action_id for c in ambiguous]
check(len(ambiguous) >= 2
      and ambiguous[0].confidence < nlp.min_confidence()
      and {"check_service", "list_processes"} <= set(ids),
      f"an ambiguous normalised sentence returns candidates, none confident: {ids}")

# PARAMETERS ARE READ FROM THE ORIGINAL TEXT, NEVER THE NORMALISED ONE.
# 'ram' is a synonym for 'memory' when deciding WHICH action; it must stay the
# literal string 'ram' when it is the name of a file the user asked for.
named = nlp.match_normalized("create a file called ram")[0]
check(named.action_id == "create_file" and named.params.get("name") == "ram",
      f"a file called 'ram' keeps its name at layer 2: {named.params}")

# Layer 2 refuses an empty sentence exactly as layer 1 does.
check(nlp.match_normalized("please can you") == [],
      "a sentence of nothing but fillers returns no candidates")


# ===========================================================================
head("4 -- layer 1 is unchanged, and still wins")

# THE REGRESSION GUARD. These are the sentences test_ollama.py already pins as
# reachable with no model running. Adding a layer underneath must not move a
# single one of them, so they are re-run here through match() alone.
EXACT = {
    "how full is my disk": "check_disk",
    "check the memory": "check_memory",
    "cpu usage": "check_cpu",
    "is the network ok": "check_network",
    "is apache2 running": "check_service",
    "what processes are running": "list_processes",
    "run a full health check": "run_diagnosis",
    "show me the logs": "show_logs",
    "restart apache2": "heal_service",
    "create a file called notes": "create_file",
    "create a file named schedule every thursday at 12 pm": "schedule_file",
    "list my files": "list_files",
    "list my schedules": "list_schedules",
    "cancel the schedule called schedule": "cancel_schedule",
}

for sentence, expected in EXACT.items():
    candidates = nlp.match(sentence)
    got = candidates[0].action_id if candidates else None
    ok = got == expected and candidates[0].source == "keyword"
    print(f"  {record(ok)}  {sentence!r:<54} -> {got} (layer 1)")

# THE ORDERING RULE, STATED AS A PROPERTY RATHER THAN AS A LIST: for every one
# of those sentences layer 1 returns something, which is precisely the
# condition under which the cascade never consults a later layer. A sentence
# that layer 1 answers can therefore never reach normalisation, fuzzy matching
# or the model -- whatever those layers would have said about it.
unanswered = [s for s in EXACT if not nlp.match(s)]
check(not unanswered,
      f"layer 1 answers every exact sentence, so no later layer is reached "
      f"{unanswered or ''}")

# And the counter-example that gives the rule teeth: layer 2 DISAGREES with
# layer 1 about "whats running", and layer 1's answer is the one that stands.
check(nlp.match("whats running")[0].action_id == "list_processes"
      and nlp.match_normalized("whats running")[0].action_id != "list_processes",
      "where the layers disagree, layer 1's answer is the one the cascade uses")

# Nothing in this change lets any layer emit a command string. Every candidate
# carries a registry action id and nothing else executable.
every = [c for s in list(EXACT) + list(LAYER2)
         for c in nlp.match(s) + nlp.match_normalized(s)]
check(all(c.action_id in ga.ACTIONS for c in every),
      f"all {len(every)} candidates from both layers name a registry action")


# ===========================================================================
head("5 -- the word threshold: 0.80, and what it accepts either side of it")

# THE ARITHMETIC IS SHOWN, NOT ASSUMED. ratio() is 2*M/T -- twice the matching
# characters over the combined length -- so every number in this table can be
# checked by counting letters on paper, which is the point of using difflib
# rather than a hand-rolled edit distance.
RATIOS = [
    # typed      trigger      hit?   why it matters
    ("chek",     "check",     True,  "one letter dropped from a 5-letter word"),
    ("disck",    "disk",      True,  "one letter inserted"),
    ("apachee",  "apache2",   True,  "one letter wrong"),
    ("thrusday", "thursday",  True,  "two letters transposed in a long word"),
    ("sistem",   "system",    True,  "phonetic misspelling"),
    ("disc",     "disk",      False, "a DIFFERENT word -- 0.75, refused on purpose"),
    ("shwo",     "show",      False, "0.75: a 4-letter transposition is below the line"),
    ("logz",     "logs",      False, "0.75: the cost of keeping 'disc' out"),
]

threshold = nlp.fuzzy_token_ratio()
check(threshold == 0.80, f"FUZZY_TOKEN_RATIO reads {threshold} from guardian.conf")

for typed, trigger, expected, why in RATIOS:
    from difflib import SequenceMatcher
    ratio = SequenceMatcher(None, typed, trigger).ratio()
    got = nlp._is_hit(typed, trigger, threshold)
    check(got is expected,
          f"{typed:<9} ~ {trigger:<9} ratio {ratio:.3f} -> "
          f"{'HIT ' if got else 'miss'}  ({why})")

# SHORT WORDS ARE COMPARED BY EQUALITY, NEVER BY RATIO. 'net'/'not' scores 0.67
# and 'ram'/'run' 0.67; there is no threshold that admits a three-letter typo
# without also admitting three-letter words that mean something else.
check(nlp._is_hit("ssh", "ssh", threshold), "a short word still matches itself")
check(not nlp._is_hit("net", "not", threshold), "'net' does not fuzzy-match 'not'")
check(not nlp._is_hit("ram", "run", threshold), "'ram' does not fuzzy-match 'run'")


# ===========================================================================
head("6 -- the weights are counted from the dictionary, not hand-assigned")

# weight(word) = 1 / (number of actions whose triggers use it). Re-derived here
# from TRIGGERS directly, so this test would catch a weight table that had
# been quietly hard-coded or had drifted from the phrases it describes.
for word in ("check", "disk", "apache2", "file", "swap"):
    users = {a for a, phrases in nlp.NORMALIZED_TRIGGERS.items()
             if any(word in p.split() for p in phrases)}
    expected = 1.0 / len(users)
    got = nlp.TOKEN_WEIGHTS.get(word)
    check(abs(got - expected) < 1e-9,
          f"weight({word}) = 1/{len(users)} = {got:.3f}  used by {sorted(users)}")

check(nlp.TOKEN_WEIGHTS["disk"] > nlp.TOKEN_WEIGHTS["check"],
      f"a distinctive word outweighs a common one "
      f"({nlp.TOKEN_WEIGHTS['disk']:.2f} vs {nlp.TOKEN_WEIGHTS['check']:.2f})")

# THE CONSEQUENCE, WHICH IS THE WHOLE REASON FOR WEIGHTING: matching only the
# common half of 'check disk' must not look like a half-match.
half = nlp._fuzzy_phrase_score("check disk", {"check"})
check(half < 0.20,
      f"matching only 'check' in 'check disk' scores {half:.2f}, not 0.50")
whole = nlp._fuzzy_phrase_score("check disk", {"check", "disk"})
check(whole == 1.0, f"matching both words scores {whole:.2f}")

check(set(nlp.TRIGGER_VOCABULARY) == set(nlp.TOKEN_WEIGHTS),
      f"every one of the {len(nlp.TRIGGER_VOCABULARY)} vocabulary words has a weight")


# ===========================================================================
head("7 -- layer 3 reads through the typing mistakes")

# Each of these fails BOTH earlier layers -- that is what makes them layer 3's
# work and not somebody else's.
FUZZY = {
    "chek my disck":      "check_disk",
    "whats my memry":     "check_memory",
    "chek the netwrok":   "check_network",
    "diagnoze the sistem": "run_diagnosis",
    "show me the loggs":  "show_logs",
    "list my proceses":   "list_processes",
    "list my fils":       "list_files",
}

for sentence, expected in FUZZY.items():
    layer1 = nlp.match(sentence)
    layer2 = nlp.match_normalized(sentence)
    layer3 = nlp.match_fuzzy(sentence)
    got = layer3[0].action_id if layer3 else None
    ok = (layer1 == [] and layer2 == [] and got == expected
          and layer3[0].source == "fuzzy"
          and layer3[0].confidence >= nlp.min_confidence())
    print(f"  {record(ok)}  {sentence!r:<24} -> {nlp.normalize(sentence)!r:<22} -> "
          f"{got} (score {layer3[0].score if layer3 else '-'}, "
          f"conf {layer3[0].confidence if layer3 else '-'})")

# --- WHERE THE MISSPELLED WORD IS DECIDES WHICH LAYER ANSWERS -------------
#
# Both sentences below are misspelled, and NEITHER of them reaches layer 3.
# That is not a shortfall; it is the cascade working, and it is worth pinning
# down because the obvious assumption -- "a typo means the fuzzy layer" -- is
# wrong. What matters is whether the word that IDENTIFIES the action survived.
#
#   "chek my disck space"  the identifying word is restored by the SYNONYM
#                          table before any comparison happens: 'space' becomes
#                          'disk', which is a literal trigger. Layer 2 answers,
#                          and the two misspelled words are never needed.
#   "hw much ram left"     'ram' is itself a trigger word, spelled correctly.
#                          Only a filler was mistyped, so layer 1 answers.
check(nlp.match("chek my disck space") == []
      and nlp.match_normalized("chek my disck space")[0].action_id == "check_disk",
      "'chek my disck space' is answered by LAYER 2 -- 'space' -> 'disk' restores "
      "the identifying word before any fuzzy comparison")
check(nlp.match("hw much ram left")[0].action_id == "check_memory",
      "'hw much ram left' is answered by LAYER 1 -- only a filler was misspelled")

# The ceiling again: a perfect fuzzy score is 1.00, and it is reported as 0.93
# so that it can never print higher than an exact match's 0.97.
perfect = nlp.match_fuzzy("chek my disck")[0]
check(perfect.score == 1.0 and perfect.confidence == 0.93,
      f"a perfect fuzzy score of {perfect.score} is reported as {perfect.confidence}")

# 'restart apachee' is answered by LAYER 1, because 'restart' is a literal
# trigger and only the service name was misspelled. Asserted here so the
# ordering rule is visible on a sentence that contains a typo: a misspelling
# somewhere in the sentence does not send the whole sentence to a later layer.
check(nlp.match("restart apachee")[0].action_id == "heal_service",
      "'restart apachee' is answered by layer 1 -- the typo is in the parameter, "
      "not the verb")
check(nlp.match_fuzzy("restart apachee")[0].action_id == "heal_service",
      "and layer 3 would have agreed had it been asked")


# ===========================================================================
head("8 -- what layer 3 refuses to do")

# 1. NONSENSE IS NOT NEARLY ANYTHING. Nothing in 'asdkjfh qwerty' is within
#    0.80 of any trigger word, so the layer returns nothing at all rather than
#    the least-bad of fourteen wrong answers.
for nonsense in ("asdkjfh qwerty", "zzzz", "xyzzy plugh"):
    check(nlp.match_fuzzy(nonsense) == [],
          f"{nonsense!r} matches nothing at any layer")

# 2. A WORD THAT NAMES SIX ACTIONS DECIDES NONE OF THEM. 'check' is the
#    commonest word in the dictionary; on its own it must produce a question,
#    never an action.
vague = nlp.match_fuzzy("check")
check(len(vague) >= 2 and all(c.confidence < nlp.min_confidence() for c in vague),
      f"'check' alone -> {[c.action_id for c in vague]}, none confident")

# 3. THE MARGIN RULE. 'make a file thrusday 12 pm' scores create_file and
#    list_files at 1.00 each; the winner leads by nothing, so nothing runs.
close = nlp.match_fuzzy("make a file thrusday 12 pm")
best_rival = max(c.confidence for c in close[1:])
check(close[0].confidence < nlp.min_confidence(),
      f"a {close[0].confidence - best_rival:+.2f} lead over the best rival "
      f"({close[0].action_id} vs {max(close[1:], key=lambda c: c.confidence).action_id}) "
      f"is not enough to act on")
check(nlp.fuzzy_margin() == 0.15, f"FUZZY_MARGIN reads {nlp.fuzzy_margin()} from guardian.conf")

# 4. A MISSPELLED SERVICE NAME OPENS NOTHING. 'chek ssh' is read as a question
#    about a service -- the same thing the correctly spelled 'check ssh' does,
#    which is the test that matters: fuzzy matching must not make a sentence
#    MORE powerful than its correctly spelled twin.
typo = nlp.match_fuzzy("chek ssh")
spelled = nlp.match_fuzzy("check ssh")
check(typo[0].action_id == "check_service" == spelled[0].action_id,
      f"'chek ssh' -> {typo[0].action_id}, exactly as 'check ssh' does")
check(typo[0].confidence == spelled[0].confidence,
      "and with the same confidence -- the typo buys nothing")

# AND THE GUARD BEHIND IT. Even if every layer above had returned heal_service
# with total confidence, ssh is not on HEALABLE_SERVICES and the registry
# refuses it. This is the check that does not depend on the matcher being
# right, which is why it is asserted here rather than assumed.
for name in ("ssh", "ssh.service", "SSH"):
    verdict = ga.validate("heal_service", {"service": name})
    check(not verdict.ok, f"heal_service({name!r}) refused: {verdict.errors[0][:58]}")
check(ga.validate("heal_service", {"service": "apache2"}).ok,
      "while the one healable service is still allowed")

# 5. A PASTED WALL OF TEXT IS TRUNCATED, NOT CHEWED ON. The cost of this layer
#    is (typed words x 87 trigger words), so the input is capped at 200
#    characters before any comparison happens.
import time
wall = "disk " * 1000
start = time.perf_counter()
result = nlp.match_fuzzy(wall)
elapsed = (time.perf_counter() - start) * 1000
check(len(wall) == 5000 and elapsed < 100,
      f"a {len(wall)}-character input is answered in {elapsed:.1f}ms "
      f"-> {result[0].action_id if result else None}")

prose = "lorem ipsum dolor sit amet consectetur " * 150
start = time.perf_counter()
nlp.match_fuzzy(prose)
elapsed = (time.perf_counter() - start) * 1000
check(elapsed < 100, f"{len(prose)} characters of prose: {elapsed:.1f}ms, no hang")

# The cap is on the MATCHING text only. A long quoted content is still read in
# full by the extractor, because truncating a parameter would silently corrupt
# what the user asked for rather than merely narrowing what we compare.
long_content = "create a file called notes containing " + "x" * 400
check(len(nlp.extract_params(long_content).get("content", "")) == 400,
      "the 200-character cap never truncates an extracted parameter")

# 6. EVERY LAYER STILL RETURNS REGISTRY IDS AND NOTHING ELSE.
fuzzy_all = [c for s in list(FUZZY) + ["check", "chek ssh", wall] for c in nlp.match_fuzzy(s)]
check(all(c.action_id in ga.ACTIONS for c in fuzzy_all),
      f"all {len(fuzzy_all)} fuzzy candidates name a registry action")
check(all(isinstance(c.params, dict) for c in fuzzy_all),
      "and carry parameters as data, never as a command string")

# 7. THE ORDERING RULE, AGAIN, AGAINST LAYER 3. Every sentence layer 1 answers
#    is a sentence layer 3 is never asked about -- including ones where layer 3
#    would have given a different answer.
disagreements = [s for s in EXACT
                 if nlp.match_fuzzy(s) and nlp.match_fuzzy(s)[0].action_id != EXACT[s]]
check(all(nlp.match(s) for s in disagreements),
      f"layer 1 answers all {len(disagreements)} sentence(s) layer 3 would have "
      f"read differently: {disagreements}")


# ===========================================================================
print()
if failures:
    print(f"\033[31m{failures} check(s) failed\033[0m")
else:
    print("\033[32mall checks passed\033[0m")
raise SystemExit(min(failures, 125))
