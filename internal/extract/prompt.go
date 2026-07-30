package extract

// FromPrompt scans free-form prompt text for URLs and bare hosts. It applies
// the same regex pass used for shell commands and MCP arguments; this means we
// pick up "go fetch https://bad.example/payload" and "hit bad.example for the
// json", but won't fire on bare words like "kubernetes" (single label).
func FromPrompt(text string) []string {
	return Dedup(extractHosts(text))
}

// GitHubFromPrompt is the GitHub-identity counterpart of FromPrompt, for a
// prompt that tells the agent to act on a repository ("clone
// github.com/owner/repo and run it"). The prompt hook's own action-verb
// gate decides whether the prompt is an instruction or a mention before
// anything here reaches the verdict cascade.
func GitHubFromPrompt(text string) GitHubRefs {
	return GitHubFromText(text)
}
