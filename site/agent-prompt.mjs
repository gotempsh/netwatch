// The set-up prompt that "Copy prompt" copies, for a coding agent to install
// netwatch and report what it sees, changing nothing without asking. Every
// command in it must exist in the released CLI: check against `netwatch --help`.

export const agentPrompt = `Set up netwatch on this machine, so you can tell me who it talks to and who is probing it.

netwatch is a traffic monitor for Linux servers and macOS: https://github.com/gotempsh/netwatch
Its documentation, as Markdown: https://gotempsh.github.io/netwatch/llms.txt
How coding agents use it: https://gotempsh.github.io/netwatch/agents.md

1. Install it, unless \`netwatch --version\` already works: curl -fsSL https://gotempsh.github.io/netwatch/install.sh | sh
   It needs root and starts netwatch in observe mode, which blocks nothing. Check \`sudo -n true\` first: if sudo wants a password, don't try it; ask me to run the command in a terminal of my own and tell you when it's done.
2. The installer adds netwatch's agent skill for Claude Code, Cursor and Codex when it finds their folders, printing "installed the netwatch ... skill at <path>". If it didn't, install it as me, not with sudo:
   - Claude Code or Cursor: \`netwatch skill --install\`
   - Codex and other agents: \`netwatch skill --install --dir ~/.agents/skills\`
   Read that SKILL.md before going on.
3. Check that it runs with \`netwatch status\`. If it can't reach the daemon, read \`journalctl -u netwatch -n 50\` (on macOS, /var/log/netwatch.log) and tell me what failed.
4. Run \`netwatch insights\` and \`netwatch sources --flagged\` right away and tell me what you find: who is probing this machine, and what each insight recommends. Don't wait for traffic; a new install has seen little, so say so and tell me what to ask you later.
5. Leave it in observe mode. Ask me before every ban, unban, allow, approval or policy change, and before switching to enforce mode. Never add --force.`;
