# Prompts Skill

How to manage and document prompts for this project.

## Directory Structure

The user will put prompts in `contrib/agents/prompts/`:

```
contrib/agents/prompts/
├── completed/      # Finished prompts with outcomes documented
└── research/       # Research notes and exploration
```

## Once you see a new prompt

Analyze the prompt and investigate the best approach to tackling it.
There are two kinds of prompts:
- Research prompts (the user will tell you if it is a research prompt)
- Implementation prompts

## Handling implementation prompts

Analyze the prompt and the complexity.
Tackle the task like a senior engineer.

In many cases, you will need extra context.
Ask for that context.

If you received a prompt called `fix_round_bug.md`, create a file called
`fix_round_bug_questions.md` where you can ask your questions. Bundle your
questions together before asking the user to answer them. Format your questions
in such a way that is easy to answer them inline.

When asking questions, provide context. What challenges do you envision, and
what guidance do you need to tackle them? You can make proposals, but in the
end the user decides.

Always ask about the commit strategy: review after each commit, or work through
the issue independently. Ask the user which approach they prefer.

Once the user has answered your questions, start implementing.
If you run into problems, ask for input.
Work with small and incremental commits.

Ensure that after every commit you can run `just checks` and `just unit`.

## Completing the prompt

You can put completed prompts in `contrib/agents/prompts/completed/`.

### Naming Convention

Use date prefixes (YYYYMMDD) for ordering:

```
20260129_short_description.md
20260130_another_task.md
```

### Format

Each completed prompt file should include:

1. **Title** - What you asked for
2. **Context** - Background information provided
3. **Outcome** - What was actually done (added after completion)

## Research Prompts

Research prompts are stored in `research/`. They ask the agent to investigate
a topic and produce a report that engineers can use to make decisions.

When executing research prompts:
- Gather evidence: read code, run tests, profile, measure. Don't speculate.
- Follow the methodology specified in the prompt (DMAIC, comparison matrix, etc.)
- Back up every claim with file paths, line numbers, or measurements
- Lead with conclusions, use tables and lists, keep it concise
