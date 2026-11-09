# Contributing

Thanks for helping. Three rules keep this tool honest.

**1. Every rule change ships with a case it must catch and a negative control.**
Add a test that the new or changed rule must block, and one that it must allow:
an ordinary command or path that is close to the pattern. The existing pairs are the
model: `rm -rf ~` blocks, `rm -rf ~/project/build` does not; `DROP TABLE users`
blocks, `DROP TABLE IF EXISTS users` does not; an edit that adds a hook to
`settings.json` blocks, an edit that adds a permission does not. Say in the pull
request how you checked the false-positive rate. A guard that fires on ordinary
work gets switched off, and then it guards nothing.

**2. Honest states stay honest.** The integrity check never reports "clean" on
something it could not see. If you add a surface, add the test for its
missing/unreadable case and assert it is NOT clean, and add the test that an
unrelated change to it is NOT drift. Both directions, every time.

**3. Credit what you borrow.**
If a contribution adapts someone else's code, rule list or idea, name the source in
the module's header comment and in the README's Credits section, and make sure its
license allows it. Material under a license that requires a notice goes in `NOTICE`.

Fixtures are synthetic and built under `tmp_path`. Each example directory carries a
`SYNTHETIC-DATA` file stating this; keep it, and add one to any new example directory.
(A test checks that every directory under `examples/` has one.) Tests never read your real
`~/.claude`: point global coverage at a fixture directory. Build dangerous command
strings from fragments, so that no test file holds a complete destructive command on
one line.

Run the tests without installing the package:

```console
python -m pip install pytest hypothesis
python -m pytest
```

The kit has no runtime dependencies and should stay that way.
