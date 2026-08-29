# guard

A pi extension that tries to balance the wants of trying to allow LLMs to do anything
and some semblance of security. It has different security tiers the user can
freely switch between, depending on the task.

There are three layers, trying to reduce possible fallout:

- a **judge** ([CARE](#1-judge--care)) that grades each command,
- a **sandbox** ([bwrap](#2-sandbox--bwrap)) that contains execution,
- **prompting** ([monke in the loop](#3-prompting-monke-in-the-loop)).

## The three components

### 1. Judge: CARE

A static pre-execution verifier, ported from
[CARE](https://github.com/prisma-research/CARE) — _"CARE: Pre-Execution Command
Verification for Shell-Executing LLM Agents"_ (ISSRE 2026,
[arXiv:2607.21642](https://arxiv.org/abs/2607.21642)).

See that repository on how it works. I do not claim any numbers with this port,
just that it's not completely broken. This is not a 1:1 port and does some things
differently.

This is the soft security boundary, that makes the monke in the loop work less, so he
doesn't get approval fatigue.

### 2. Sandbox: bwrap

Containment for approved bash commands. Each command runs inside bubblewrap.

The hard security boundary. Stops fallout from bad commands that weren't found by
the judge. Mounts the minimal amount of dirs needed to be realistically usable.
All the secret files aren't visible by default. Well, except if you stored your secrets in /tmp
or something.

Also hard excludes paths from the CARE paper, so there is at least some sort of hard fallback for these.

#### Sandboxing and ssh

`~/.ssh` is completely hidden in normal operation. Of course, you may want
the agent to be able to ssh somewhere, which you can toggle with `/guard allow-ssh`.
This passes through your `SSH_AUTH_SOCK` _and_ your `~/.ssh` dir (ro) to the agent.

This is a usability tradeoff. The way I use ssh is to have all the keys in the agent
and identifying public keys mapped to the ones in the ssh agent in `~/.ssh`. For this
kind of usage, this is fine. If you however store your private keys in `~/.ssh`, this
of course allows the agent full access to exfiltrate them.

### 3. Prompting: monke in the loop

Sadly we still need a monke to avoid the LLM from going off the rails and
assure the quality of its output.

The monke will be prompted depending on what the LLM wants to do/read.
Current project is fully unprompted readable, everything else gets prompted to assure
that the LLM doesn't read shell history or w/e.

To assure that the monke at least pretends to read the edits to the codebase,
all writes and edits are prompted for.

Another important feature is that the bash scripts that get displayed to the user are formatted
via shfmt, because LLMs like to produce code golfed scripts that are hard to read for monke.

## Safety tiers

TODO

## TODOs and problems

- Hole in deny logic for CARE: Just let the agent write down something destructive in a bash script. Then
  execute it: CARE grade downgraded

## Invariants

- Judge returning a DENY _always_ stops the script from executing, so the chance of the monke
  accidentally deleting his hard drive is lower
- Judge never executes anything. No shell expansion etc.
- Auto-allow should only be possible when the sandbox is enabled
