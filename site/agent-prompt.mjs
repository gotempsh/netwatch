// The set-up prompt that "Copy prompt" copies, for a coding agent to install
// netwatch and report what it sees, changing nothing without asking.

export const agentPrompt = `Set up netwatch on this machine, so you can tell me who it talks to and who is probing it.

netwatch is a traffic monitor for Linux servers and macOS: https://github.com/gotempsh/netwatch
Its documentation, as Markdown: https://gotempsh.github.io/netwatch/llms.txt

1. Install it: curl -fsSL https://gotempsh.github.io/netwatch/install.sh | sh
   It needs root and starts netwatch in observe mode, which blocks nothing. If sudo asks for a password, ask me to run the command in a terminal of my own.
2. Install its agent skill and read it: npx skills add gotempsh/netwatch
3. Check that it runs with \`netwatch status\`. If it can't reach the daemon, read \`journalctl -u netwatch -n 50\` (on macOS, /var/log/netwatch.log) and tell me what failed.
4. Give it a few minutes, then run \`netwatch insights\` and \`netwatch sources --flagged\` and tell me what you find: who is probing this machine, and what each insight recommends.
5. Leave it in observe mode. Ask me before every ban, unban, allow, approval or policy change, and before switching to enforce mode. Never add --force.`;
