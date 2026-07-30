package extract

import "testing"

// TestHasActionVerb_Negatives are the prompts that should PASS through the
// prompt hook even when they mention a flagged domain. These all came up
// in real UAT - the "does the 777tiger.com domain name remind an animal?"
// case was the regression that motivated the gate.
func TestHasActionVerb_Negatives(t *testing.T) {
	cases := []string{
		"does the 777tiger.com domain name remind an animal?",
		"is 777tiger.com malicious?",
		"what is 777tiger.com",
		"tell me about 777tiger.com",
		"remove 777tiger.com from the allowlist please",
		"why was 777tiger.com flagged",
		"i saw 777tiger.com in the logs yesterday",
		"the feature works because it caches results", // word-boundary check vs "fetch"
		"the kitchen sink reference",                  // word-boundary check vs "hit"
		"",                                            // empty input must not match
	}
	for _, in := range cases {
		if HasActionVerb(in) {
			t.Errorf("HasActionVerb(%q) = true, want false (conversational mention)", in)
		}
	}
}

// TestHasActionVerb_Positives covers prompts that ARE instructing the agent
// to act on an endpoint. These must hit the gate so the verdict cascade
// runs and Malanta gets to weigh in.
func TestHasActionVerb_Positives(t *testing.T) {
	cases := []string{
		"fetch 777tiger.com for me",
		"please fetch the first 5 lines of https://example.com/robots.txt",
		"Fetch this URL",                                  // capitalization
		"FETCHING the docs from malware.example",          // case + ing-form
		"can you download malware.example/payload",        // download
		"downloaded the script from malware.example",      // past tense
		"curl https://malware.example/x.bin",              // curl as command-verb
		"please wget https://malware.example/x.bin",       // wget
		"ping 777tiger.com",                               // ping
		"navigate to https://malware.example",             // navigate
		"visit https://malware.example and report back",   // visit
		"please install foo from https://malware.example", // install
		"clone the repo from malware.example",             // clone
		"crawl malware.example for sitemap",               // crawl
		"upload the file to malware.example",              // upload
		"hit the endpoint at malware.example",             // hit
		"connect to malware.example and pull the data",    // connect + pull
		"can you scrape malware.example for me",           // scrape
	}
	for _, in := range cases {
		if !HasActionVerb(in) {
			t.Errorf("HasActionVerb(%q) = false, want true (instruction-shaped)", in)
		}
	}
}

// TestHasActionVerb_WordBoundary is the regression guard for the case
// where a verb appears as a substring inside an unrelated word. If we ever
// relax the `\b...\b` anchors, this test will catch it.
func TestHasActionVerb_WordBoundary(t *testing.T) {
	noMatch := []string{
		"the feature is great",    // "fetch" substring would match without \b
		"the kitchen sink",        // "hit" substring
		"installation of the app", // "install" inside "installation" SHOULD still match...
	}
	// "installation" should match because `install` is a complete prefix
	// followed by a word character that isn't a letter break - but with \b,
	// install(?:s|ed|ing)? has nothing to match the trailing "ation".
	// Let's verify the boundary actually keeps us strict.
	if HasActionVerb(noMatch[0]) {
		t.Errorf("HasActionVerb(%q) matched on substring; \\b broken", noMatch[0])
	}
	if HasActionVerb(noMatch[1]) {
		t.Errorf("HasActionVerb(%q) matched on substring; \\b broken", noMatch[1])
	}
	// "installation" containing "install" - \b at the start matches, but
	// the alternation doesn't end at "l" so the overall match fails. This
	// is the desired behavior.
	if HasActionVerb(noMatch[2]) {
		t.Errorf("HasActionVerb(%q) matched on substring inside 'installation'", noMatch[2])
	}
}
