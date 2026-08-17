#!/usr/bin/env python3
"""
Linux Guardian -- guardian_nlp.py                                  (Phase 6)

THE DETERMINISTIC MATCHER. Turns a sentence a human typed into one action id
from the registry, plus whatever parameters it can find in the sentence.

THIS FILE CONTAINS NO AI AND NEEDS NO NETWORK. That is the point. It is
attempt number 1 of three:

    1. this file          -- a dictionary of trigger phrases. Always available.
    2. Ollama             -- only if this file found nothing AND Ollama is up.
    3. show the list      -- if neither matched. Never guess, never execute.

Because step 1 covers every action on its own, the console keeps working with
Ollama stopped, uninstalled, or never heard of. The model is an optional
convenience for unusual phrasings, not a dependency.

WHAT THE MATCHER IS AND IS NOT ALLOWED TO DO
--------------------------------------------
It returns an ACTION ID and some candidate PARAMETERS. It does not build a
command, does not touch the filesystem, and does not decide whether anything
runs. Everything it returns is handed to guardian_actions.validate(), which
re-checks the id against the registry and every parameter against its declared
pattern. A wrong guess here is a bad suggestion, never a security problem.
"""

import re
from difflib import SequenceMatcher

from guardian_actions import (
    ACTIONS,
    _DAYS,
    normalise_day,
    normalise_name,
    normalise_service,
    normalise_time,
)
from guardian_config import read_config


# ===========================================================================
#  1. THE TRIGGER DICTIONARY
# ===========================================================================
#
# Each action maps to the phrases a person might actually type. Phrases are
# written WITHOUT filler words ('a', 'the', 'my', 'please'), because those are
# stripped from the user's sentence before matching -- see _tokenise below.
#
# HOW TO READ A PHRASE: every word in it must appear in the sentence. A
# two-word phrase is therefore harder to match than a one-word phrase, and
# scores higher when it does, because it is better evidence. That is the whole
# ranking rule, and it is why 'create file' beats a bare 'disk' on the sentence
# "create a file called disk".
TRIGGERS = {
    "check_disk": [
        "disk", "disk space", "disk usage", "storage", "hard drive",
        "free space", "check disk", "full disk", "space left",
    ],
    "check_memory": [
        "memory", "ram", "memory usage", "check memory", "free memory",
        "swap",
    ],
    "check_cpu": [
        "cpu", "processor", "cpu usage", "load average", "check cpu",
        "how busy",
    ],
    "check_network": [
        "network", "internet", "connectivity", "ping", "gateway",
        "check network", "online", "connection",
    ],
    "check_service": [
        "service status", "check service", "status service", "service running",
        "running",
    ],
    "list_processes": [
        "processes", "processes running", "top processes", "list processes",
        "busiest", "cpu hogs", "what running", "heaviest processes",
    ],
    "run_diagnosis": [
        "diagnosis", "diagnose", "health", "health check", "health score",
        "check everything", "full check", "how healthy", "scan system",
        "overall status",
    ],
    "show_logs": [
        "logs", "log", "show logs", "audit trail", "history",
        "recent actions", "what happened",
    ],
    "heal_service": [
        "heal", "fix", "restart", "recover", "repair", "bring back",
        "heal service", "start service", "restart service", "start apache",
    ],
    "create_file": [
        "create file", "make file", "new file", "write file", "create note",
        "make note", "save file", "create text file",
    ],
    # NOTE ON THE OVERLAP WITH create_file: several of these share the word
    # "file". They do not collide, because ranking is on EVIDENCE (trigger
    # words matched + parameters the action can use), and create_file consumes
    # a name where list_files consumes nothing. "create a file named notes"
    # therefore beats list_files 3-2, while "list my files" beats create_file
    # 2-0. The tests pin both cases.
    "list_files": [
        "list files", "show files", "what files", "my files", "which files",
        "workspace", "list workspace", "file exists", "find file",
        "file named", "files there",
    ],
    "schedule_file": [
        "schedule", "schedule file", "every week", "weekly", "recurring",
        "automate", "repeat weekly", "create every",
    ],
    "list_schedules": [
        "list schedules", "show schedules", "scheduled tasks", "list timers",
        "show timers", "what scheduled", "my schedules",
    ],
    "cancel_schedule": [
        "cancel schedule", "delete schedule", "remove schedule",
        "stop schedule", "unschedule", "cancel timer", "remove timer",
    ],
}


# Filler words carrying no clue about WHICH action is wanted. Removing them
# lets "create a file" match the phrase "create file" as a contiguous run,
# which is stronger evidence than two words that merely both appear somewhere.
#
# The list is deliberately short. Every word removed here is a word that can no
# longer distinguish two actions, so this is not a place to be generous.
STOPWORDS = {
    "a", "an", "the", "my", "me", "i", "please", "can", "you", "to", "of",
    "is", "are", "it", "some", "just", "want", "would", "like", "for",
    "on", "in", "at", "and", "do", "does", "get", "give", "tell", "there",
}


# ===========================================================================
#  1B. NORMALISATION -- THE MACHINERY OF LAYER 2
# ===========================================================================
#
# WHAT LAYER 2 IS FOR. Layer 1 asks "did the user type one of our phrases?".
# It is exact, and exactness is why it is first. But a person who types
#
#       "whats my hdd at"
#
# has said something this project understands perfectly well; they have simply
# used a different noun for the same thing. Sending that to a language model
# would be absurd -- there is no intent to interpret, only a word to translate.
# Layer 2 does the translating with two tables, and it is every bit as
# deterministic as layer 1: the same sentence produces the same answer on every
# machine, with no network and no model.
#
# THE ONE PROPERTY THAT MAKES THIS SAFE TO REASON ABOUT: normalize() is applied
# to BOTH SIDES -- to the user's sentence and to the trigger phrases (see
# NORMALIZED_TRIGGERS below). Adding a synonym therefore cannot make the two
# sides disagree, because there is only one function and both sides go through
# it. A table that rewrote the sentence but not the dictionary would silently
# break a trigger every time somebody extended it.
#
# ON THE SPELLING of the name: the rest of this project is British
# ('normalise_day', '_tokenise'). normalize() keeps the brief's spelling
# because the brief names the four cascade layers, and a reader following the
# brief should find the function it names.

# --- the synonym table ----------------------------------------------------
# Everyday word -> the word this project's triggers actually use.
#
# WHY THESE AND NOT MORE: every entry is a word that means the SAME THING as
# its canonical term, not merely a word that often appears near it. 'ssd' is a
# disk; 'fast' is not, however often the two are typed together. The moment
# this table starts holding associations rather than synonyms it becomes a
# guessing machine, and guessing is what layers 3 and 4 are for -- with
# thresholds and an ambiguity rule to keep them honest.
#
# NO ENTRY'S VALUE IS ANOTHER ENTRY'S KEY. That is deliberate and it is tested
# (test_nlp.py section 2): it makes normalisation a single pass with no chain
# to follow, and it is what makes normalize() idempotent.
SYNONYMS = {
    # storage
    "storage": "disk", "hdd": "disk", "ssd": "disk", "space": "disk",
    # memory
    "ram": "memory", "mem": "memory",
    # processor
    "processor": "cpu",
    # networking
    "net": "network", "internet": "network", "wifi": "network",
    # systemd vocabulary
    "daemon": "service", "unit": "service",
    # the one service this project actually heals
    "apache": "apache2", "httpd": "apache2",
}


# --- the filler table -----------------------------------------------------
# Words that say nothing about WHICH action is wanted.
#
# WHY THIS IS A SECOND LIST AND NOT AN EXTENSION OF STOPWORDS: STOPWORDS
# belongs to layer 1, and layer 1 must keep behaving exactly as it did before
# this change -- otherwise the ordering rule ("a lower layer always wins") is
# meaningless, because the lower layer would have moved. FILLERS is strictly
# larger and strictly later. Layer 1 is frozen; layer 2 is allowed to be
# braver, because anything it sees has already failed layer 1.
#
# 'how' and 'much' are the interesting entries. They appear inside real trigger
# phrases ('how busy', 'how healthy'), which is exactly why stripping them from
# one side only would be a bug -- and exactly why both sides go through the
# same function.
#
# 'what' sits beside 'whats' on purpose. Leaving one out would make the table
# introduce the very asymmetry it exists to remove: "whats running" would
# normalise to "running" while the trigger "what running" stayed two words, and
# they would stop matching each other.
#
# IT IS BUILT AS A UNION SO THAT 'STRICTLY LARGER' IS TRUE AND NOT MERELY
# INTENDED. The first draft of this table listed the new words only, which
# quietly made it larger in some places and SMALLER in others -- layer 1
# discarded 'at' while layer 2 kept it. A word layer 1 has already judged
# meaningless cannot become meaningful one layer later, so the union is the
# only shape that makes sense, and test_nlp.py section 2 asserts the subset
# relation rather than trusting this comment.
FILLERS = STOPWORDS | {
    "whats", "what", "how", "much",
}


# Characters kept when punctuation is stripped: letters, digits, ':' so that
# '12:00' survives as one token, and '_' '-' because both are legal in a
# Guardian file name and _tokenise (layer 1) already keeps them. Splitting
# 'my-notes' into two words here, when layer 1 treats it as one, would make the
# two layers disagree about what a word is.
_PUNCTUATION = re.compile(r"[^a-z0-9:_-]+")


def _canonical(word):
    """One word through the synonym table, tolerating a single trailing 's'.

    'units' and 'daemons' are the same request as 'unit' and 'daemon', and a
    table that only knew the singular would leave that hole open for the fuzzy
    layer to fall into -- which would be the wrong layer doing the wrong job,
    since this is a plural, not a typo.

    THE PLURAL IS ONLY TRIED WHEN THE SINGULAR IS ACTUALLY A KEY, so this can
    never invent a word: 'processes' asks about 'processe', finds nothing, and
    is returned untouched. It is the same one-trailing-'s' rule _same_word
    already uses for matching, applied to the table so the two agree.
    """
    if word in SYNONYMS:
        return SYNONYMS[word]
    if word.endswith("s") and word[:-1] in SYNONYMS:
        return SYNONYMS[word[:-1]]
    return word


def normalize(text):
    """Lower-case, de-punctuate, apply synonyms, drop fillers, collapse spaces.

    Returns a STRING, not a token list, because a string is what a person can
    read in a test report and in the console: "hw much ram left" becoming
    "hw memory left" explains itself at a glance.

    THE ORDER IS SYNONYMS BEFORE FILLERS, and it is load-bearing. A synonym may
    introduce a canonical term, and every term this function produces must then
    face the filler pass; doing it the other way round would let a word slip
    through unexamined because it did not exist yet when the filter ran.

    IT NEVER RETURNS None AND NEVER RAISES. An input of pure punctuation
    normalises to the empty string, which the caller reads as 'nothing to match
    on' -- the same answer _tokenise gives for the same input.
    """
    lowered = text.lower()

    # Punctuation becomes a SPACE rather than being deleted, so "cpu,disk"
    # becomes two words instead of the single nonsense word "cpudisk". Same
    # reasoning as _tokenise; the two functions differ in their tables, not in
    # their idea of what a word boundary is.
    cleaned = _PUNCTUATION.sub(" ", lowered)

    words = []
    for word in cleaned.split():
        canonical = _canonical(word)
        if canonical in FILLERS:
            continue
        words.append(canonical)

    # str.split() already collapsed every run of whitespace; joining with a
    # single space is what puts that guarantee into the returned string.
    return " ".join(words)


def normalize_tokens(text):
    """normalize() as a word list. The matcher wants tokens, reports want text."""
    return normalize(text).split()


# EVERY TRIGGER PHRASE, NORMALISED ONCE AT IMPORT.
#
# Once, not per request: there are ~110 phrases and the console is asked to
# answer while a person waits. More importantly it is the same call the user's
# sentence gets, so the two sides cannot drift apart.
#
# A phrase that normalised to nothing would be a silent hole in the dictionary
# -- an action that layer 2 could never reach. None currently do, and
# test_nlp.py section 2 fails the build if a future edit creates one. Duplicates
# are dropped ('disk' and 'storage' both become 'disk') while keeping the
# original order, so scoring never sees the same phrase twice.
def _dedupe_words(phrase):
    """Drop repeated words inside one phrase, keeping the first of each.

    THE TABLE CREATES THESE. 'disk space' has two distinct words, but 'space'
    is a synonym for 'disk', so it normalises to 'disk disk'. Left alone, that
    phrase would score the single word 'disk' in a sentence as TWO words
    matched -- inflating this action's evidence above a rival that genuinely
    matched two different words. The sentence contained one idea and must be
    credited with one.

    It also merges 'disk space' into the phrase 'disk', which the caller then
    discards as a duplicate. Fewer phrases, none of them lying.
    """
    seen = []
    for word in phrase.split():
        if word not in seen:
            seen.append(word)
    return " ".join(seen)


def _normalize_triggers(triggers):
    normalized = {}
    for action_id, phrases in triggers.items():
        seen = []
        for phrase in phrases:
            candidate = _dedupe_words(normalize(phrase))
            if candidate and candidate not in seen:
                seen.append(candidate)
        normalized[action_id] = seen
    return normalized


NORMALIZED_TRIGGERS = _normalize_triggers(TRIGGERS)


# ===========================================================================
#  1C. DISTINCTIVENESS -- THE MACHINERY OF LAYER 3
# ===========================================================================
#
# WHY A WEIGHT AT ALL. Layer 3 asks "which action's words does this sentence
# nearly contain?", and counting matched words alone answers it badly, because
# the words are not worth the same. Eleven of the fourteen actions have a
# trigger phrase containing 'check'; exactly one contains 'disk'. Hearing
# 'check' eliminates almost nothing, while hearing 'disk' settles the question
# outright. A scorer that treats them as one word each will happily rank
# check_cpu and check_disk equal on the sentence "chek my disck".
#
# HOW THE WEIGHT IS DECIDED -- BY COUNTING, NOT BY OPINION:
#
#       weight(word) = 1 / (number of ACTIONS whose triggers contain it)
#
# A word naming one action is worth a whole point. A word shared by four is
# worth a quarter, because hearing it leaves four possibilities standing. This
# is the idea behind inverse document frequency, in the one-line form that can
# be checked by hand in a viva: the numbers below are the reciprocals of counts
# anyone can verify by reading TRIGGERS.
#
# IT IS COMPUTED, NEVER HAND-ASSIGNED. Nobody has to remember to re-tune a
# table after editing a trigger phrase -- adding 'check my disk' to another
# action makes 'check' automatically worth less, everywhere, at import.
def _token_weights(normalized_triggers):
    """Count how many ACTIONS use each word, and invert it."""
    actions_using = {}
    for action_id, phrases in normalized_triggers.items():
        for word in {w for phrase in phrases for w in phrase.split()}:
            actions_using.setdefault(word, set()).add(action_id)
    return {word: 1.0 / len(users) for word, users in actions_using.items()}


TOKEN_WEIGHTS = _token_weights(NORMALIZED_TRIGGERS)

# Every distinct word any trigger phrase contains. The fuzzy comparison runs
# against this set ONCE per query rather than per phrase: there are ~110
# phrases but only ~90 distinct words in them, and a word compared once is a
# word not compared eleven times.
TRIGGER_VOCABULARY = tuple(sorted(TOKEN_WEIGHTS))


# ===========================================================================
#  2. TURNING A SENTENCE INTO TOKENS
# ===========================================================================
def _tokenise(text):
    """Lower-case, drop punctuation, drop filler words, return a word list.

    Punctuation becomes a SPACE rather than being deleted, so "cpu,disk"
    becomes two words instead of the single nonsense word "cpudisk".
    """
    lowered = text.lower()

    # Replace every character that is not a letter, digit, underscore or
    # hyphen with a space. Hyphen and underscore survive because they are
    # legal in a Guardian file name.
    cleaned = re.sub(r"[^a-z0-9_-]+", " ", lowered)

    return [w for w in cleaned.split() if w and w not in STOPWORDS]


def _same_word(a, b):
    """Compare two words, tolerating a simple plural.

    'schedules' should match the trigger word 'schedule', and 'logs' should
    match 'log'. Full stemming would need a library and would turn 'processes'
    into something that no longer matches 'process'; one trailing 's' covers
    every case this project actually has, and it is obvious what it does.
    """
    return a == b or a == b + "s" or b == a + "s"


def _phrase_score(phrase, tokens):
    """Score one trigger phrase against the tokenised sentence.

    Returns (matched_word_count, confidence). Confidence rises with the LENGTH
    of the phrase that matched, because a longer phrase is stronger evidence:
    "create file" matching is far more telling than "file" matching.
    """
    words = phrase.split()

    # How many of the phrase's words appear anywhere in the sentence.
    matched = sum(1 for w in words if any(_same_word(t, w) for t in tokens))

    if matched == len(words):
        # Every word is present. Now ask the harder question: do they appear
        # CONSECUTIVELY? "create file" appearing as a run is better evidence
        # than "create" at the start and "file" at the end.
        contiguous = _contains_run(tokens, words)
        if contiguous:
            return matched, min(0.97, 0.78 + 0.06 * len(words))
        return matched, min(0.93, 0.72 + 0.05 * len(words))

    # A partial match: at least two words, and at most one missing. Scores
    # below MATCH_MIN_CONFIDENCE on purpose, so it becomes a SUGGESTION the
    # user picks from rather than something that runs.
    if matched >= 2 and matched >= len(words) - 1:
        return matched, 0.55 + 0.05 * matched

    return 0, 0.0


def _contains_run(tokens, words):
    """True if `words` appear consecutively inside `tokens`."""
    for start in range(len(tokens) - len(words) + 1):
        window = tokens[start:start + len(words)]
        if all(_same_word(t, w) for t, w in zip(window, words)):
            return True
    return False


# ===========================================================================
#  3. PULLING PARAMETERS OUT OF THE SENTENCE
# ===========================================================================

# Service words people use, mapped to the unit name the project actually
# monitors. 'apache' is by far the commonest way to say 'apache2'.
_SERVICE_WORDS = {
    "apache": "apache2", "apache2": "apache2", "httpd": "apache2",
    "webserver": "apache2", "web": "apache2",
    "ssh": "ssh", "sshd": "ssh",
}

# 'called X' / 'named X' is how people name things in English. The character
# class here is deliberately WIDER than the one the validator accepts: the
# extractor's job is to find what the user meant, and the validator's job is to
# refuse it if it is not allowed. Extracting '../etc/passwd' and then rejecting
# it with a clear message is far better than silently failing to see it.
_NAME_PATTERNS = [
    re.compile(r"""['"]([^'"]{1,60})['"]"""),
    re.compile(r"\b(?:called|named|name)\s+(?:(?:a|an|the|my|new)\s+)*([^\s,]{1,60})",
               re.IGNORECASE),
    # The '(?:(?:a|an|the|my|new)\s+)*' group skips filler words between the
    # noun and the actual name. Without it, "schedule a report every monday"
    # captures the word "a" -- grammatically the next word, but obviously not
    # what the user called their file. The '*' allows several ("schedule a new
    # report"), and captures nothing when there are none.
    re.compile(r"\b(?:file|note|schedule|timer)\s+(?:(?:a|an|the|my|new)\s+)*([^\s,]{1,60})",
               re.IGNORECASE),
]

_CONTENT_PATTERN = re.compile(
    r"\b(?:content|containing|contains|saying|says|with text|that says)\s+(.+)$",
    re.IGNORECASE,
)

# A time written any of the ways a person writes one.
_TIME_PATTERN = re.compile(
    r"\b(\d{1,2}[:.]\d{2}\s*(?:am|pm)?|\d{1,2}\s*(?:am|pm)|noon|midnight)\b",
    re.IGNORECASE,
)

# Words that appear right before a name but are never the name itself.
_NOT_A_NAME = {
    "it", "this", "that", "them", "one", "file", "note", "the",
    "a", "an", "my", "new", "every", "at", "on",
}


def extract_params(text):
    """Find every parameter the sentence contains. Never validates.

    Returns only what it actually found -- a missing key means 'not mentioned',
    which the validator will report as a required parameter if the chosen
    action needs it.
    """
    found = {}
    tokens = _tokenise(text)

    # --- service ---------------------------------------------------------
    for token in tokens:
        if token in _SERVICE_WORDS:
            found["service"] = _SERVICE_WORDS[token]
            break

    # --- day -------------------------------------------------------------
    # _DAYS is imported from guardian_actions so the console and the validator
    # agree on what counts as a day. One dictionary, not two.
    for token in tokens:
        if token in _DAYS:
            found["day"] = normalise_day(token)
            break

    # --- time ------------------------------------------------------------
    time_match = _TIME_PATTERN.search(text)
    if time_match:
        found["time"] = normalise_time(time_match.group(1))

    # --- name ------------------------------------------------------------
    for pattern in _NAME_PATTERNS:
        match = pattern.search(text)
        if match:
            candidate = match.group(1).strip().strip(".,;:")
            if candidate.lower() in _NOT_A_NAME:
                continue
            # A day or a time is never the file name, even when it follows the
            # word 'schedule' -- "schedule thursday" means WHEN, not WHAT.
            if candidate.lower() in _DAYS or _TIME_PATTERN.fullmatch(candidate):
                continue
            found["name"] = normalise_name(candidate)
            break

    # --- content ---------------------------------------------------------
    content_match = _CONTENT_PATTERN.search(text)
    if content_match:
        found["content"] = content_match.group(1).strip().strip("'\"")

    return found


# ===========================================================================
#  4. THE MATCHER
# ===========================================================================
class Candidate:
    """One possible reading of the sentence.

    evidence is the number the ranking is actually decided on: trigger words
    matched PLUS parameters this action can use. It is kept as an attribute
    rather than a local so the console can show WHY one reading beat another.
    """

    def __init__(self, action_id, confidence, phrase, params, evidence=0):
        self.action_id = action_id
        self.confidence = round(confidence, 2)
        # The score this reading EARNED, kept unchanged even when the ambiguity
        # rule lowers `confidence` below the threshold. The two are different
        # questions and the console shows different ones:
        #   confidence      -> may this run without asking?
        #   raw_confidence  -> how good was this reading? (shown in the picker)
        # Without the split, the picker would list the winner at a clamped 0.74
        # above a runner-up at 0.84 and look sorted wrongly.
        self.raw_confidence = round(confidence, 2)
        self.phrase = phrase
        self.params = params
        self.evidence = evidence
        self.source = "keyword"
        # The raw fuzzy score, before the parameter bump and before the
        # ceiling. None on every other layer, because there is no such number
        # there -- an exact match did not 'score 1.0', it simply matched. It is
        # declared here rather than attached in match_fuzzy() so that every
        # candidate has the attribute and no caller has to ask which layer
        # produced the object before reading it.
        self.score = None

    def __repr__(self):
        return f"<{self.action_id} {self.confidence} via {self.phrase!r}>"


def usable_params(action_id, found):
    """Narrow the parameters found in a sentence to those THIS action declares.

    It does two jobs at once, and both matter.

    1. IT DECIDES THE RANKING. The count it produces is what disambiguates two
       actions that share a verb:

           "create a file named schedule every thursday at 12 pm"

       contains 'create' and 'file', a perfect match for create_file. It also
       contains a day and a time. create_file declares only name and content,
       so it can use 1 of the 3 parameters found; schedule_file declares name,
       day and time and uses all 3. Reading a sentence as the action that
       accounts for MORE of what was actually said is both the better answer
       and an easy one to defend: an interpretation that throws away two thirds
       of the request is a bad interpretation, however well its verb matched.

    2. IT KEEPS THE REQUEST HONEST. Whatever it drops never reaches the
       validator. extract_params() reads the sentence before anything knows
       which action will win, so it finds a name in "check if there is a file
       named test" -- and list_files has no parameters at all. Passing that
       name through made validate() refuse with "does not take a parameter
       called 'name'", blaming the user for an artefact of our own matcher.

    validate() is still strict about undeclared parameters, and should be: an
    explicit API call naming one IS an error. The filtering belongs here, where
    a guess is being turned into a request. guardian_ollama._vet does the same
    thing to the model's answer, for the same reason.
    """
    declared = {p["name"] for p in ACTIONS[action_id]["params"]}
    return {key: value for key, value in found.items() if key in declared}


def min_confidence():
    """The threshold, read from guardian.conf so it is tunable in one place."""
    try:
        return float(read_config().get("MATCH_MIN_CONFIDENCE", "0.75"))
    except ValueError:
        return 0.75


def _rank(tokens, params, triggers, ceiling, source, limit):
    """Score every action against a token list. Shared by layers 1 and 2.

    IT IS ONE FUNCTION ON PURPOSE. Layer 2 differs from layer 1 in exactly two
    things -- which tokens it is given and which trigger table it reads -- and
    both are parameters here. Copying the scorer so the normalised layer could
    have 'its own' would mean the ambiguity rule, the evidence ranking and the
    plural tolerance all existed twice, and a fix to one would silently miss
    the other.

    `ceiling` is the highest confidence this layer may ever report. Layer 1
    keeps 0.97; layer 2 is capped at 0.95 so that a translated match can never
    present itself as more certain than a literal one. It is a CEILING and not
    a constant: a weak or ambiguous normalised reading must still be able to
    score below the threshold, or the ambiguity rule would be switched off for
    exactly the layer that needs it most.
    """
    scored = []

    for action_id, phrases in triggers.items():
        best_score = 0.0
        best_matched = 0
        best_phrase = None

        for phrase in phrases:
            matched, score = _phrase_score(phrase, tokens)
            # Rank on (words matched, then confidence). Matching two trigger
            # words always beats matching one, which is what stops the single
            # word 'disk' from outranking the pair 'create file'.
            if (matched, score) > (best_matched, best_score):
                best_matched, best_score, best_phrase = matched, score, phrase

        if best_score > 0:
            # EVIDENCE = trigger words matched + parameters this action can
            # use. Both halves are things the sentence really contained, which
            # is why they are added rather than one being a tie-breaker: an
            # action matching one verb but consuming three parameters has
            # accounted for more of the sentence than one matching two verbs
            # and consuming one.
            # Only ever hand an action the parameters it declares -- see
            # usable_params() for why this both ranks and protects.
            usable = usable_params(action_id, params)
            fit = len(usable)
            confidence = min(ceiling, best_score + 0.03 * fit)
            candidate = Candidate(action_id, confidence, best_phrase, usable,
                                  evidence=best_matched + fit)
            candidate.source = source
            scored.append(candidate)

    # Sort by evidence first, then confidence. Ties broken by id so the order
    # is reproducible -- a demo that lists candidates in a different order each
    # run is a demo that is hard to trust.
    scored.sort(key=lambda c: (-c.evidence, -c.confidence, c.action_id))

    # --- THE AMBIGUITY RULE ----------------------------------------------
    # Two readings that account for the sentence EQUALLY well, with almost the
    # same confidence, means the sentence genuinely did not say which was
    # wanted. Rather than pick, the winner's confidence is pulled below the
    # threshold, which makes the console show the choices instead of running
    # one of them. Refusing to guess is the same instinct as HEALABLE_SERVICES:
    # when unsure, do nothing.
    #
    # The comparison is on EVIDENCE, not confidence alone. Two actions with
    # different evidence are not ambiguous even if their confidences happen to
    # be close -- one of them demonstrably explained more of the sentence.
    if (len(scored) >= 2
            and scored[0].evidence == scored[1].evidence
            and abs(scored[0].confidence - scored[1].confidence) < 0.05):
        scored[0].confidence = min(scored[0].confidence, min_confidence() - 0.01)

    return scored[:limit]


def match(text, limit=3):
    """LAYER 1 -- exact keyword matching. Returns a list of Candidates.

    The list is ordered best first and never contains an action that scored
    zero. An EMPTY list is a real and expected answer -- it means 'I do not
    know', and the cascade then tries the next layer rather than guessing.

    NOTHING ABOUT THIS LAYER CHANGED when normalisation was added. It reads the
    same tokens through the same STOPWORDS and the same TRIGGERS, and reports
    the same ceiling of 0.97. That is what makes "a lower layer always wins" a
    statement about behaviour rather than about intentions: the layer that wins
    first is byte-for-byte the one that was already there.
    """
    tokens = _tokenise(text)
    if not tokens:
        return []
    return _rank(tokens, extract_params(text), TRIGGERS, 0.97, "keyword", limit)


def match_normalized(text, limit=3):
    """LAYER 2 -- the same matching, after synonyms and fillers are resolved.

    Reached only when layer 1 returned nothing at all, so it can never override
    or reorder an exact match; it is asked exclusively about sentences the
    literal dictionary had no opinion on.

    WHY IT IS NOT MERELY A SECOND TRY: the input has been rewritten, and so has
    the dictionary, by the same function. "whats my hdd at" and the trigger
    "disk" are not close as strings and never will be -- no amount of fuzzy
    comparison in layer 3 would connect 'hdd' to 'disk', because they share one
    letter. Only a table knows they are the same thing. That is why layer 2
    exists ahead of layer 3 instead of being folded into it.

    Parameters still come from extract_params() reading the ORIGINAL text.
    Normalisation is for deciding WHICH action; it must never be what a file
    name is read out of, or a file the user called 'ram' would be created as
    'memory'.
    """
    tokens = normalize_tokens(text)
    if not tokens:
        return []
    return _rank(tokens, extract_params(text), NORMALIZED_TRIGGERS, 0.95,
                 "normalized", limit)


# ---------------------------------------------------------------------------
#  LAYER 3 -- FUZZY MATCHING
# ---------------------------------------------------------------------------
#
# THE FORMULA, IN ONE PLACE, BECAUSE IT HAS TO BE DEFENDED OUT LOUD:
#
#   a WORD HIT    SequenceMatcher(None, typed, trigger).ratio() >= 0.80
#   a PHRASE      score = (sum of weights of its words that were hit)
#                       / (sum of weights of all its words)
#   an ACTION     score = the best score among its phrases
#   ACCEPTED      only if score >= 0.75 AND it leads the runner-up by >= 0.15
#
# The division is what makes phrases of different lengths comparable: hitting
# one word of a one-word phrase and two words of a two-word phrase both give
# 1.0, and hitting one word of a two-word phrase gives less than either. The
# weights are what stop the common half of a phrase carrying it -- matching
# only 'check' in 'check disk' scores 0.167/1.167 = 0.14, not 0.5.
#
# THE THREE NUMBERS AND WHY THEY ARE NOT SOMETHING ELSE:
#
#   0.80 per word.  A five-letter word with one letter wrong scores about 0.89
#     ('disck'/'disk', 'chek'/'check'), so 0.80 accepts real typing while
#     refusing 'disk'/'disc' at 0.75 -- a pair that a HUMAN should join in the
#     synonym table, deliberately, rather than a similarity score joining them
#     by accident. At 0.70 'log' starts matching 'load' and 'ram' matching
#     'run', and the matcher becomes confidently wrong, which is worse than
#     being unsure.
#
#   0.75 per action.  The same MATCH_MIN_CONFIDENCE the console already uses to
#     decide whether an action may run without being chosen from a list, read
#     from the same config key -- not a second threshold that could drift away
#     from the first. WHY NOT 0.60: on this dictionary 0.60 is the score of a
#     phrase whose distinctive word was MISSED and whose common words landed
#     ('check service' matching only 'service' scores 0.75, and 'free memory'
#     matching only 'free' scores 0.33). Accepting at 0.60 would mean acting on
#     sentences where the word that identifies the action never appeared. The
#     threshold is not tuned to a corpus; it is set where "the identifying word
#     was actually there" stops being true.
#
#   0.15 lead.  Fuzzy scores are ratios, and in practice a genuine winner leads
#     by 0.4 or more (measured: 'chek my disck space' gives check_disk 1.00 and
#     the nearest rival 0.25). A lead under 0.15 therefore does not mean "close
#     call", it means the sentence never distinguished the two actions at all,
#     and the honest answer is the picker.
#
# WHAT IT CANNOT DO. It returns action ids from the registry and parameters
# read by the regexes in extract_params(). No score of any size lets it emit a
# command, skip validate(), or reach a write action without the confirm step.


def fuzzy_token_ratio():
    """How alike two words must be. From guardian.conf; 0.80 if unreadable."""
    try:
        return float(read_config().get("FUZZY_TOKEN_RATIO", "0.80"))
    except ValueError:
        return 0.80


def fuzzy_margin():
    """How far ahead the winner must be. From guardian.conf; 0.15 if unreadable."""
    try:
        return float(read_config().get("FUZZY_MARGIN", "0.15"))
    except ValueError:
        return 0.15


# A pasted wall of text is truncated to this many characters before any
# comparison happens.
#
# THE COST IS A PRODUCT, WHICH IS WHY THIS EXISTS: every typed word is compared
# against all 87 trigger words, so the work grows with the length of the input.
# 200 characters is about 35 words -- longer than any real request to a console
# whose whole vocabulary is 14 actions -- and caps the comparison at roughly
# 3,000 short-string ratios, which is milliseconds. Without the cap, pasting a
# log file would be an easy way to make the web process sit and think.
#
# TRUNCATION IS SAFE HERE IN A WAY IT WOULD NOT BE ELSEWHERE: this is the layer
# that decides WHICH action, and no sentence needs 200 characters to say which
# of fourteen things it wants. Parameters are still read from the full text by
# extract_params(), so a long quoted file content is never cut short.
FUZZY_MAX_CHARS = 200

# Words shorter than this are compared by equality only, never by ratio.
#
# WHY: at three characters a single wrong letter scores 0.67 and the ratio can
# no longer tell a typo from a different word -- 'net'/'not', 'ram'/'run',
# 'log'/'lot' are all one letter apart and all mean different things. There is
# no threshold that accepts the typo and refuses the other word, so the only
# honest comparison for a short word is whether it is the same word.
FUZZY_MIN_LENGTH = 4


def _is_hit(typed, trigger, threshold):
    """Would a human call these the same word?

    difflib.SequenceMatcher.ratio() is 2*M/T -- twice the number of matching
    characters over the total length of both words. It is used rather than a
    hand-written edit distance because it ships with Python (the brief forbids
    new packages), and because a reader can check any number it produces by
    counting letters.

    real_quick_ratio() is an upper bound computed from the lengths alone. When
    even that bound cannot reach the threshold the expensive comparison is
    skipped entirely, which is what keeps a long input cheap.
    """
    if len(trigger) < FUZZY_MIN_LENGTH or len(typed) < FUZZY_MIN_LENGTH:
        return typed == trigger

    matcher = SequenceMatcher(None, typed, trigger)
    if matcher.real_quick_ratio() < threshold or matcher.quick_ratio() < threshold:
        return False
    return matcher.ratio() >= threshold


def fuzzy_hits(tokens, threshold=None):
    """Which trigger words the sentence contains, allowing for misspelling.

    Returns a SET of trigger vocabulary words. Computing it once per query --
    rather than once per phrase -- is what makes the layer cheap: the phrases
    are then scored by set lookup, with no further string comparison at all.
    """
    if threshold is None:
        threshold = fuzzy_token_ratio()

    # dict.fromkeys rather than set(): duplicates are removed while the order
    # stays the order the user typed, so a debugging print reads naturally.
    unique = list(dict.fromkeys(tokens))

    hits = set()
    for trigger in TRIGGER_VOCABULARY:
        for typed in unique:
            if _is_hit(typed, trigger, threshold):
                hits.add(trigger)
                break
    return hits


def _fuzzy_phrase_score(phrase, hits):
    """The weighted share of one phrase's words that were hit."""
    words = phrase.split()
    total = sum(TOKEN_WEIGHTS.get(w, 1.0) for w in words)
    if total == 0:
        return 0.0
    earned = sum(TOKEN_WEIGHTS.get(w, 1.0) for w in words if w in hits)
    return earned / total


def match_fuzzy(text, limit=3):
    """LAYER 3 -- the same dictionary, read through a spell-checker.

    Reached only when layers 1 and 2 both returned nothing, so it can never
    override an exact or a normalised match.

    The input is normalised first, so layer 3 inherits every synonym and filler
    layer 2 knows: 'chek my disck space' becomes 'chek disck disk' before a
    single ratio is computed. The two layers compose rather than compete --
    which is why 'hdd' resolving to disk is layer 2's job and 'disck' resolving
    to disk is layer 3's, and neither has to know about the other.
    """
    tokens = normalize_tokens(text[:FUZZY_MAX_CHARS])
    if not tokens:
        return []

    hits = fuzzy_hits(tokens)
    if not hits:
        return []

    params = extract_params(text)
    scored = []

    for action_id, phrases in NORMALIZED_TRIGGERS.items():
        best_phrase, best_score = None, 0.0
        for phrase in phrases:
            score = _fuzzy_phrase_score(phrase, hits)
            if score > best_score:
                best_phrase, best_score = phrase, score

        if best_score <= 0:
            continue

        # Parameters count here exactly as they do in layers 1 and 2. An action
        # that can use the day AND the time in the sentence has accounted for
        # more of what was said than one that can use neither, and that is true
        # whether the verb was spelled correctly or not.
        usable = usable_params(action_id, params)
        fit = len(usable)

        # THE CEILING IS 0.93, one step below layer 2's 0.95 and layer 1's
        # 0.97. A perfect fuzzy score is 1.00 -- every word of some phrase was
        # hit -- and printing 1.00 beside an exact match's 0.97 would tell the
        # reader the guess was the more certain of the two. The ladder means
        # the number itself says which layer answered.
        confidence = min(0.93, best_score + 0.03 * fit)

        # `evidence` stays comparable with the other layers: things the
        # sentence really contained. A fuzzy hit is counted as a word matched.
        matched_words = sum(1 for w in best_phrase.split() if w in hits)
        candidate = Candidate(action_id, confidence, best_phrase, usable,
                              evidence=matched_words + fit)
        candidate.source = "fuzzy"
        candidate.score = round(best_score, 2)
        scored.append(candidate)

    scored.sort(key=lambda c: (-c.evidence, -c.confidence, c.action_id))

    # --- THE MARGIN RULE -------------------------------------------------
    # Two readings within 0.15 of each other means the sentence did not say
    # which was wanted. The winner's confidence is pulled below the threshold
    # -- the same mechanism layers 1 and 2 use -- so the console shows both and
    # asks, instead of running one of them. raw_confidence is left alone, so
    # the picker can still show how each reading actually scored.
    #
    # THE RUNNER-UP IS THE BEST RIVAL, NOT SIMPLY THE NEXT ROW. The list is
    # ordered by evidence first, so a rival with a HIGHER confidence can sit
    # further down -- "make a file thrusday 12 pm" scores create_file and
    # list_files at 1.00 each, and create_file leads only because it matched
    # two words instead of one. Comparing against the next row alone would have
    # measured the gap to a third reading and called that a clear win. Taking
    # the maximum is the conservative reading of "beats the runner-up", and
    # conservative is the right direction for a rule whose job is to refuse.
    if len(scored) >= 2:
        best_rival = max(c.confidence for c in scored[1:])
        if scored[0].confidence - best_rival < fuzzy_margin():
            scored[0].confidence = min(scored[0].confidence, min_confidence() - 0.01)

    return scored[:limit]


def best_match(text):
    """The single confident answer, or None.

    None means one of two different things, and the console tells them apart by
    looking at whether match() returned anything:
        no candidates at all  -> "I do not understand"
        candidates, none sure -> "did you mean one of these?"
    """
    candidates = match(text)
    if candidates and candidates[0].confidence >= min_confidence():
        return candidates[0]
    return None


# ===========================================================================
#  5. THE CASCADE -- keyword, then Ollama, then give up
# ===========================================================================
def resolve(text):
    """Work out what the user meant, in three attempts. Returns (candidates, source).

    ATTEMPT 1  the keyword matcher above. It covers every action in the
               registry unaided, so this is the path the demo takes and the
               only one that has to work.

    ATTEMPT 2  Ollama, and ONLY when attempt 1 found nothing at all. Note what
               that ordering buys: a local model can never override, reorder or
               second-guess a deterministic match. It is consulted exclusively
               about sentences the dictionary had no opinion on, so adding or
               removing it cannot change any behaviour that already worked.

    ATTEMPT 3  nothing. An empty list, which the console renders as "not
               understood" together with the list of things it can do.

    `source` is returned so the console can say which one answered. During a
    demonstration that matters: it is the difference between "the AI did this"
    and "a dictionary did this, the AI was not even running".
    """
    candidates = match(text)
    if candidates:
        return candidates, "keyword"

    # Imported here rather than at the top of the file so that this module has
    # NO import-time dependency on the Ollama code at all. guardian_nlp must
    # keep working if guardian_ollama.py is deleted outright.
    try:
        import guardian_ollama
    except ImportError:
        return [], "none"

    answer = guardian_ollama.classify(text)
    if not answer:
        return [], "none"

    # THE MODEL CLASSIFIES; THE REGEXES EXTRACT.
    # Any parameter the deterministic extractor found in the sentence overrides
    # the model's version of it. A model asked about Thursday can answer
    # "Friday" with total confidence; a regex that matched the literal word in
    # the text cannot.
    params = dict(answer["params"])
    params.update(extract_params(text))

    candidate = Candidate(
        answer["action_id"],
        answer["confidence"],
        phrase="ollama",
        params=params,
        evidence=0,
    )
    candidate.source = "ollama"
    return [candidate], "ollama"


def ollama_model():
    """The configured model name, for showing in the UI."""
    return read_config().get("OLLAMA_MODEL", "llama3.2:1b")


def ollama_status():
    """One line describing whether the optional model is usable. Never raises."""
    try:
        import guardian_ollama
    except ImportError:
        return False, "guardian_ollama.py is not installed"
    try:
        return guardian_ollama.probe()
    except Exception as exc:                      # noqa: BLE001 - see below
        # A broad except is deliberate and is confined to a STATUS function.
        # Its only job is to put a sentence on a web page; there is no
        # circumstance in which failing to describe an optional component
        # should be allowed to break the console that does not need it.
        return False, f"probe failed: {exc}"
