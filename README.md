# pi agent config

Personal pi setup. I care about not letting the agent nuke my PC, so the most interesting
part of this repo is the multi layered guard extension. There is a hard sandbox that
tries to contain the blast radius of the agent, a soft sandbox that analyzes commands and
something similar to claudes auto mode to reduce fatigue. It also tries to balance
the slop production aspect with manual prompting for writes. Well, except if you don't want it.
Maximum flexibility is the most important part.

Another feature is that things hard fail unlike in claude code. If it can't run sandboxed,
it will not run _at all_.

Secrets are included in the repo via sops. I want this to be maximally portable.

It has tests! WOW!
