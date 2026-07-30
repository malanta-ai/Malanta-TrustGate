package extract

import "regexp"

// promptActionVerbRe matches whole-word execution-intent verbs that indicate
// the prompt is instructing the agent to *act on* a network endpoint, as
// opposed to merely talking about one. The regex is case-insensitive and uses
// `\b` boundaries so substrings inside larger words ("feature" must not match
// "fetch", "kitchen" must not match "hit") are excluded.
//
// The verb set is intentionally curated to favor PRECISION over recall:
//   - Strong network verbs: fetch, download, retrieve, curl, wget, ping,
//     scrape, crawl, navigate, visit, browse.
//   - Package / source-fetching verbs: install, clone.
//   - Data movement: upload, exfiltrate.
//   - HTTP-style mid-strength verbs: request, hit, connect, pull, push.
//
// Deliberately excluded as too-noisy in everyday English: get, go, run,
// open, use, call, query, find, look, send, post, reach, access. Including
// these would re-introduce the "asking about a domain" false positive that
// motivated the gate in the first place. The shell hook still catches the
// actual execution if any of those phrasings result in a real network call.
//
// Each entry uses Go's non-capturing group syntax (?:...) so we don't pay for
// captures we never inspect.
var promptActionVerbRe = regexp.MustCompile(`(?i)\b(?:` +
	`fetch(?:es|ed|ing)?|` +
	`download(?:s|ed|ing)?|` +
	`retriev(?:e|es|ed|ing)|` +
	`curl|wget|nslookup|dig|whois|telnet|netcat|ncat|` +
	`ping(?:s|ed|ing)?|` +
	`scrap(?:e|es|ed|ing)|` +
	`crawl(?:s|ed|ing)?|` +
	`navigat(?:e|es|ed|ing)|` +
	`visit(?:s|ed|ing)?|` +
	`brows(?:e|es|ed|ing)|` +
	`install(?:s|ed|ing)?|` +
	`clon(?:e|es|ed|ing)|` +
	`exfiltrat(?:e|es|ed|ing)|` +
	`upload(?:s|ed|ing)?|` +
	`request(?:s|ed|ing)?|` +
	`hit(?:s|ting)?|` +
	`pull(?:s|ed|ing)?|` +
	`push(?:es|ed|ing)?|` +
	`connect(?:s|ed|ing)?` +
	`)\b`)

// HasActionVerb reports whether `text` contains an execution-intent verb
// suggesting the prompt is instructing the agent to *do* something with a
// network endpoint, as opposed to merely mentioning one.
//
// This is the gate behind the "ask vs do" distinction in beforeSubmitPrompt:
//
//   - "is 777tiger.com malicious?"            -> false (talk about it)
//   - "does 777tiger.com remind an animal?"   -> false (talk about it)
//   - "fetch 777tiger.com for me"             -> true  (act on it)
//   - "please curl https://777tiger.com/x"    -> true  (act on it)
//   - "install foo from 777tiger.com"         -> true  (act on it)
//
// Trade-off: this is a heuristic, not a parser. A motivated attacker can
// phrase an instruction without any listed verb ("would you mind grabbing
// the file at 777tiger.com/x.bin?") and slip past the prompt hook. That
// failure still meets the shell hook at execution time when the agent
// actually attempts the network call, so the architectural property the
// POC promises - "no hostile domain is contacted without Malanta weighing
// in" - is preserved by the layered design, not by this gate alone.
func HasActionVerb(text string) bool {
	if text == "" {
		return false
	}
	return promptActionVerbRe.MatchString(text)
}
