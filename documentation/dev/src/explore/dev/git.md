# Git for developers

This page only focuses on git from a developer perspective as [maintenance](./maintenance.md) is considered as a distinct role (although they are by no means exclusive).

This goal of this page is to document the best practices for developers that are easy to follow so that:

- Dealing with source control doesn't get in the way of getting things done and instead aids in getting them done to a good standard. As developers of a distributed system, we should be using git (arguably the most widely used distributed system) effectively, which in turn makes our collaboration more efficient.
- Aid in PR review process to make it easier to apply fix-up commits while maintaining a readable history.
- Allow the maintainers to merge PRs with a readable history in the main branch and to backport patches when needed.
- Make it easier to `git bisect` issues when needed.

It is not a goal of this page to explain the details of `git` that can be found documented elsewhere.

## The official branches

- `base`: a convenience branch which always points to the latest
  *minor* release (i.e., `vX.Y.0`). This is suitable for making the
  front page on web views (not Github, however, which inexplicably
  couples the front page with the default pull request target). Nothing
  is ever merged here; it is fast-forwarded to each new minor release
  tag as it happens.

- `release`: mainline branch from which minor releases are built.
  Topics which have lived on `draft` for a while and passed whatever QA
  is in place for releasable topics can be merged here.

- `draft`: scratch branch for merging all topics whose owners consider
  them finished and which pass a basic review to. Is deleted and
  restarted on each minor release.

## General guidelines

There is usually more than one way to do something in git and there are many details that are up for personal preference. This section only contains the important details that we have consensus on and we should collectively enforce these rules in PRs.

- Prefer to make commits that don't break the build when possible.
  - When it's hard to avoid, in commits that do break the build add a trailing line with `Bisect: skip`.
- Prefer to make atomic commit. That is commits that only make changes that cannot be divided any further (of course taking into consideration the rule above). See more details in the section [Making commits](#making-commits).
- Prefer to open PRs that focus on a single issue. A reasonable exception is when a feature or a fix happens to close multiple issues and it's not feasible to divide it.
- The commit message should concisely capture the essence of the change. First line shouldn't be longer than 72 characters. When a more detailed description is needed, it should go on following lines. In such case, consider if the changes can be divided into multiple commits.
- Avoid overriding changes applied in some predecessor commit in another commit in the same PR. Prefer to use `fixup!` commits that can be auto-squashed to the commits that first introduced the change before the PR is merged. See git-absorb recommended in the [tooling](#appendix-b-tooling) section if you want to automate this.
- Start development branches off the last tagged release, unless it depends on another open PR, in which case start off that. If your branch depends on multiple open PRs, merge them on top of a release as a base for your branch. Exception to the rule is that sometimes breaking changes in CI require a new base point that is not a tagged release in order for the PRs to be able to pass the CI checks. In this case, the new base point must be communicated to the dev team by the maintenance team. See more details in the section [Creating a new topic](#creating-a-new-topic) and [Considerations on base points](#considerations-on-base-points).
- Never merge `main` (with an exception for long-lived [integration branches](#integration-branches)) or `draft` (no exceptions) branch into your development branch.
- Write the base of a PR in its description (e.g. "based on v0.x.x" or "based on #123 and #124"). Keep it up-to-date if you change the base.
- Never merge other branches into your branch in between your commits. If your branch depends on another one, it should be based on it.
- Prefer to make the last commit of a branch the changelog commit. Use the description for the changelog commit "Changelog: #123" where "123" should be replaced with your PR number. This helps to navigate commits easier and selecting the right commit range for reviews, especially for stacked branches with a longer dependency chain.

## Creating a new topic

In general, when starting a new topic, base its branch on the latest
minor release tag (`vX.Y.0`). Include your name in the branch name to
indicate that you own it, e.g. `ray/topic-1`. (Git branch names are
paths, with their components separated by `/`; in many repositories,
the "top level"; branch names without a `/` belongs to the repository
maintainers for specific official branches.)

For example:

```
% git checkout -b ray/topic-1 v1.2.0
```

Or, if you prefer `git switch`:

```
% git switch -c ray/topic-1 v1.2.0
```

There are two main exceptions:

- topics which depend on other topics not yet in a release should be
  based on the end of the topic they depend on. e.g., if
  `ray/topic-2` is a continuation of `ray/topic-1`, start it with
  `git checkout -b ray/topic-2 ray/topic-1`.

  It is best to do this on finished topics, but if `ray/topic-1`
  were unfinished and changed out from under you, a command to rebase
  `ray/topic-2` onto it is:

  ```
  % git rebase [hash of first commit on ray/topic-2] --onto ray/topic-1
  ```

  Make sure that your local copy of the first topic is updated,
  however, or this operation will do nothing.

- topics which are bugfixes, which should be based on the commit which
  introduced the bug being fixed. You can find this commit in
  logarithmic time with `git bisect`:

  ```
  % git bisect start
  % git bisect bad [a commit or tag which has the bug]
  % git bisect good [a known good version]
  ```

  NB: `new` and `old` can be used instead of `bad` and `good`,
  respectively, which may be more comfortable if the behavior being
  identified is not precisely a bug.

  The bisection will then begin to select commits, which can be built
  and checked for the bug and marked good or bad with `git bisect good`
  or `git bisect bad` (omitting the argument means the currently
  checked out commit).

  If this guide has largely been followed, this process should be
  straightforward and lead to a bug-introducing commit. If the history
  is odd, bisection sometimes leads to merge commits instead; this is
  sometimes correct (the merge introduced the bug somehow) and
  sometimes the result of a weird history. In either case, the commit
  `bisect` found is likely fine to base the bugfix on.

  Basing bugfixes on commits which introduce the bugs they fix
  guarantees that the bugfix can be merged into any potential
  maintenance release or release candidate easily. It also links the
  bug and bugfix together when reading the history.

## Making commits

You can do whatever is useful to you locally, but making smaller
commits more frequently is probably better because it is easier to
merge two commits than split one.

Before making commits, you should probably set your email to a work
email in the repository configuration, with `git config --local
user.email <work email here>`.

To aid in making smaller commits, you can use `git add -p`. This
prompts you with each individual change in your worktree and asks
whether you want to add it to the index; you can answer `y` or `n` to
these prompts. There are other options as well; the most important is
`s` for split, used when Git identified something too large as a single
change. Once you have selected the changes you want, you can `git
commit`.

A commit message looks something like this:

```
component: do something

Do something in component.
```

The first line maps to the subject line of an email, and the remaining
lines map to the email body. The usual format for the subject line is
`component: short commit message`. `component` identifies a component
changed by this commit; it could be something like `tests/e2e` or `ci`
or `vp_token`, but generally it should help direct the reader to the
parts of the system you are changing. The rest of the short message is
a present tense sentence describing what the commit does; this is
sometimes described as "imperative mood" but it is not quite and I
prefer "commit message present ense".

The rest of the message provides the actual description of what the
commit does, and should ideally be verbose. You can refer to earlier
commits by hash here; if you do, include their short message as well
(e.g., `In abcde123 ("component: do something"), we did something.`).

Every commit should individually build and be correct on its own,
though this is probably not the case while you are developing. If you
find an error in an earlier commit you made, you can commit the fix
with `git commit --fixup=[hash]`, where `hash` is the hash of the
commit you are fixing up. This creates a fixup commit (the message will
start with `fixup!`) which can be used in rerolling later.

Once your messy development work is done, you can change it to meet
style by rerolling. I will be using `git reroll` in examples, which is
an alias for `git rebase --interactive --keep-base --autosquash`. I use
this alias because `rebase` and `rebase --interactive` are essentially
entirely different operations which confusingly use the same command;
`rebase` is, as discussed above, for changing what a branch is based
on, but `reroll` is for editing a branch.

To reroll a branch you have checked out, you need to provide an
upstream to tell Git where your branch actually starts; this is just
whatever your branch is based on. For example, you could do `git reroll
v1.2.3`, or `git reroll someoneelse/topic-i-need`. This selects commits
for rerolling which are present on your branch but not in the upstream.

When you run this command, Git will generate a script in the
interactive rebase language for you, and open a text editor on it. The
command list of this language is always there in a comment below. If
you do not edit anything, the commands will all be `pick`, which just
keeps the commit unchanged, except that if you made `--fixup` commits,
those commits will be moved right after the commit they are fixing up
and their command will be `fixup`. If there were merges present in your
branch (which there should not be on a topic branch), they will not be
present, which is correct (rerolling and keeping merges is possible,
but only useful in advanced situations discussed in the maintainer
section).

The most important commands are:

- `pick`: use this commit. Note that if you reorder lines in the
  script, the commits will be reordered as well. This doesn't work if
  they actually depend on one another, but you can sometimes reorder
  independent changes for clarity.

- `reword`: edit the commit message. This opens a text editor on the
  commit message the same way that making the commit does.

- `fixup`: keep the changes in this commit, but include them in the
  commit on the previous line. Generally after a `pick`, and the
  functionality of `--autosquash` will automatically set up your fixup
  commits with this command.

- `edit`: After applying the commit, drop back out to the command line,
  where you can manually edit it with `git commit --amend`. When
  finished, continue with `git rebase --continue`. This is also the
  only way to split a commit into two; use `edit` on the commit you
  want to split, and when you are dropped out to the command line, use
  `git reset HEAD~1` to back it out but keep the changes in the
  worktree. Then use `git add -p` to partially add the changes, making
  as many commits as you like, and use `git rebase --continue` when
  finished. Optionally, note the hash of the commit you are splitting
  and use `git commit -c [hash]` to keep the same timestamps and log
  message of the commit you are splitting and open an editor to change
  the message to something more specific.

- `drop`: don't use this commit at all. Deleting the line from the
  script also has this effect.

If your terminal editor is something like `vi`, then `git config --user
rebase.abbreviateCommands true` may be useful - it makes Git generate
the script with the single-letter commands instead of the full-word
commands. Replacing a single letter with `r` in a `vi`-like editor is
much faster than replacing a word.

## Collaboration branches

- When you're collaborating with someone else on a branch and you make a commit before you pull their changes, do not merge, but rebase your commit onto the remote version instead. There is no need to merge in this situation and it creates a tangle in history, but it's what `git` offers to do by default. You can stop it from doing this by setting your git config to `pull.ff = only`.
- Prefer not to force-push when the branch is still in progress as that makes it harder for the other part(y/ies) to sync.  Instead use `fixup!` commits that can be squashed later when the branch is being finalized.

## Integration branches

Integration branches can be short-lived (in between releases) or long-lived (spanning multiple releases). They're typically used to merge multiple related development branches into a single one. Short-lived branches are typically used to test related PR together and integration branch is not merged into `main`. In long-lived branches it's common to sync them with latest tagged releases by merging the release into the integration branch with a goal of eventually merging the integration branch into some future release.

## Considerations on base points

The default base point, ceteris paribus, is the most recent minor
release tag. This only bears repeating to emphasize that "an arbitrary
point on `release`" is not the default base point.

However, the best base point will often be different. Identifying and
possibly correcting it is a maintainer's job more than a contributor's,
but it is sometimes helpful for contributors to be on the same page, so
a few lines are included in the contributor's guide as well.

Sometimes a topic depends on another topic. This is different from "a
conflict is introduced if they are both naively 3-way merged" -
dependency may not introduce any conflict at all on the textual level,
and textual conflicts may not indicate a dependency. If a topic depends
on another topic, it should be based on that topic. For example, suppose
`alice/topic-1` is based on `v1.7.0`, and `bob/topic-2` depends on
Alice's topic. Then `bob/topic-2` should be based on the last commit of
`alice/topic-1`. They are still separate topics, so they should be
merged separately, with `alice/topic-1` first.

Rarely, a topic may depend on multiple other topics simultaneously. This
should be quite rare, since in cases where this happens, the topics
probably depend on one another as well, and can simply be organized one
on top of another. If it does happen, the topic could potentially be
based on a merge of the topics it depends on (e.g., `charlie/topic-3`
which depends on independent `alice/topic-1` and `bob/topic-2` can begin
with `v1.7.0`, merge `alice/topic-1` and `bob/topic-2`, and make commits
afterward) to preserve this dependency information. If a point on
`release` is chosen, this information is lost, but at the very least a
sensible sync point like a changelog batch, or the merge of the last of
the depended-upon topics, should be chosen rather than an arbitrary
point. Additional commit message information would be necessary in this
case.

If a topic is specifically a bugfix, then the commit which introduced
the bug should be identified (e.g., with `bisect`), and the bugfix
should be based on that commit. It is a trivial graph theorem that this
will be mergeable into anything downstream which contained the bug.

There will sometimes be long-lived branches which outlive a single minor
release cycle. These branches may just be extended topic branches, which
began from some release tag in the past; new minor release tags should
be merged into the long-lived branch as they happen (the tag should be
merged, not `release`, for a more informative merge message). This is
just about the only exception to the rule that merges should flow only
from topic branches into integration branches. Shorter branches, or even
long branches if the owner prefers it, should just be rebased onto the
new tag.

It is also possible that a long-lived branch is a subordinate
integration branch of its own. A branch like this has its own
maintainer, and integrates its own topics. These branches should also
merge minor release tags as they occur; their new topics can then be
based off this merge, which is like the "minor release tag" in the
context of that branch.

## Example: the lifecycle of a topic

Suppose we have the following simple program in a repository:

```
/* version 0.1.0 */

#include <stdio.h>
#include <sys/mman.h>

int main(int argc, char **argv)
{
        void *p = mmap(NULL,
                       1048576,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
                       0);

        printf("mapped 1MB at %p\n", p);

        return 0;
}
```

The example history is:

```
% git log --graph --abbrev-commit
* commit cccfb78 (HEAD, tag: v0.1.0, release, base, draft)
| Author: Alice <alice@example.com>
| Date:   Thu May 12 14:40:37 2022 -0400
|
|     version 0.1.0
|
* commit 291d127
  Author: Contributors <contributors@example.com>
  Date:   Thu May 12 14:35:51 2022 -0400

      prehistory
```

Alice decides to start a new feature topic:

```
% git checkout -b alice/map-two-megabytes
Switched to a new branch 'alice/map-two-megabytes'

[Alice edits the program]

% git add -p
diff --git a/program.c b/program.c
index cb5e816..0a4e160 100644
--- a/program.c
+++ b/program.c
@@ -6,7 +6,7 @@
 int main(int argc, char **argv)
 {
        void *p = mmap(NULL,
-                      1048576,
+                      2097152,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
(1/1) Stage this hunk [y,n,q,a,d,e,?]? y

% git commit
[alice/map-two-megabytes 2f54b40] main: mmap two megabytes
 1 file changed, 1 insertion(+), 1 deletion(-)
```

However, concurrently, Bob is working on a different topic:

```
% git checkout -b bob/macro-memory-units v0.1.0
Switched to a new branch 'bob/macro-memory-units'

[Bob edits the program]

% git add -p
diff --git a/program.c b/program.c
index cb5e816..a6ec4ce 100644
--- a/program.c
+++ b/program.c
@@ -3,10 +3,13 @@
 #include <stdio.h>
 #include <sys/mman.h>

+#define KB 1024
+#define MEG 1048576
+
 int main(int argc, char **argv)
 {
        void *p = mmap(NULL,
-                      1048576,
+                      1 * MEG,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
(1/1) Stage this hunk [y,n,q,a,d,s,e,?]? y

% git commit
[bob/macro-memory-units b72f024] main: use macros for memory size units
 1 file changed, 4 insertions(+), 1 deletion(-)
```

Both of these topics are submitted, and Alice merges them to `draft`.

```
% git checkout draft
Switched to branch 'draft'

% git merge alice/map-two-megabytes
Merge made by the 'ort' strategy.
 program.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

% git merge bob/macro-memory-units
Auto-merging program.c
CONFLICT (content): Merge conflict in program.c
Recorded preimage for 'program.c'
Automatic merge failed; fix conflicts and then commit the result.
```

Alice looks at the conflict, and because she has `merge.conflictStyle =
diff3` turned on, it looks like this:

```
int main(int argc, char **argv)
{
        void *p = mmap(NULL,
<<<<<<< HEAD
                       2097152,
||||||| cccfb78
                       1048576,
=======
                       1 * MEG,
>>>>>>> bob/macro-memory-units
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
                       0);
```

It's easy enough to see that the resolution is `2 * MEG` here, which
would be a little harder if this setting were not on and the middle
(common ancestor's version) part of the conflict were not present.

After the conflict is fixed, `draft` looks like this:

```
% git log --oneline --graph
*   b74fd2a (HEAD -> draft) Merge branch 'bob/macro-memory-units' into draft
|\
| * c39987c (bob/macro-memory-units) main: use macros for memory size units
* |   74c3119 Merge branch 'alice/map-two-megabytes' into draft
|\ \
| |/
|/|
| * 2f54b40 (alice/map-two-megabytes) main: mmap two megabytes
|/
* cccfb78 (tag: v0.1.0, release, base) version 0.1.0
* 291d127 prehistory
```

When Alice tests `draft`, she discovers a bug:

```
% ./program
mapped 1MB at 0x7f71a92b8000
```

The program prints that it mapped 1MB when it mapped 2MB. This is an
error in `alice/map-two-megabytes`, so that topic can't graduate to
`release`. Bob's topic is fine, however.

```
% git checkout release
Switched to branch 'release'

% git merge bob/macro-memory-units
Merge made by the 'ort' strategy.
 program.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)
```

Alice fixes her branch:

```
% git checkout alice/map-two-megabytes
Switched to branch 'alice/map-two-megabytes'

[Alice edits the program here]

% git add -p
diff --git a/program.c b/program.c
index 0a4e160..f543c30 100644
--- a/program.c
+++ b/program.c
@@ -12,7 +12,7 @@ int main(int argc, char **argv)
                       -1,
                       0);

-       printf("mapped 1MB at %p\n", p);
+       printf("mapped 2MB at %p\n", p);

        return 0;
 }
(1/1) Stage this hunk [y,n,q,a,d,e,?]? y

% git commit --amend
[alice/map-two-megabytes df8697a] main: mmap two megabytes
 Date: Thu May 12 14:50:48 2022 -0400
 1 file changed, 2 insertions(+), 2 deletions(-)
```

Alice reverts the old `alice/map-two-megabytes` on `draft` with `git
revert -m 1 74c3119` (the commit hash of the merge), resolving the
conflict in reverse this time (introduced because a textually new line
was introduced on `draft`; if either the left or right side had been
taken directly, this would not occur).

Then, Alice merges the new `alice/map-two-megabytes`:

```
% git merge alice/map-two-megabytes
Auto-merging program.c
CONFLICT (content): Merge conflict in program.c
Resolved 'program.c' using previous resolution.
Automatic merge failed; fix conflicts and then commit the result.
```

The textual conflict encountered is, again, `1048576` to `1 * MEG` on
one side, and `1048576` to `2097152` on the other. Since this has
already been encountered, Git remembered it, because Alice has
`rerere.enabled = true` in her configuration, and the conflict is
automatically resolved - it just needs to be `git add`ed. (If
`rerere.autoUpdate` is on, even this step can be skipped.)

This time, `program` is successfully tested, and Alice can merge her own
topic into `release`:

```
% git checkout release
Switched to branch 'release'

% git merge alice/map-two-megabytes
Auto-merging program.c
CONFLICT (content): Merge conflict in program.c
Resolved 'program.c' using previous resolution.
Automatic merge failed; fix conflicts and then commit the result.

% git add program.c && git commit
```

Even though the branches are merged in the opposite order this time, the
recorded resolution still applies - `rerere` automatic resolution is
purely textual, not history-based.

The final history of `release` looks like this:

```
% git log --oneline --graph
*   4043280 (HEAD -> release) Merge branch 'alice/map-two-megabytes' into release
|\
| * df8697a (alice/map-two-megabytes) main: mmap two megabytes
* |   f5e6f35 Merge branch 'bob/macro-memory-units' into release
|\ \
| |/
|/|
| * c39987c (bob/macro-memory-units) main: use macros for memory size units
|/
* cccfb78 (tag: v0.1.0, base) version 0.1.0
* 291d127 prehistory
```

## Common issues

This sections goes into some common issues and some hints on how you can
resolve them.

With most things in git you start again, so don't be held back by a fear of making mistakes. The only thing where caution is needed is pushing to `main` branch and even more severe with tags, which should considered to be permanent. Neither of these should be done by developers and are responsibility of the maintenance team.

### Base branch has been updated

TODO

### Tangled history

TODO

### Too many commits that touch the same locations

TODO

### Too little commits that could be divided

TODO

### Accidentally overridden a local branch

If you accidentally lost some work by e.g. overriding it by another version from remote, you can consult `git reflog` that has a list of your previous commits that you will be able to recover from there.

## Appendix A: Useful git configuration settings

- `merge.ff = false` in combination with `alias.ff = merge --ff-only`

  Rather than having to deal with git's somewhat troublesome
  "fast-forward if possible, else make a merge commit" default behavior,
  set `merge` to always make a merge commit, and use the `ff` alias to
  fast-forward when desired.

- `pull.ff = only`, `push.default = nothing`

  Some extra guardrails when pulling and pushing integration branches
  from and to a remote. Pushes will require a remote and branch name to
  be explicitly given. I never use `pull`, preferring `fetch` and `ff`
  in combination, but if you want to use it, setting `pull.ff = only` is
  a must.

- `rebase.abbreviateCommands = true`

  Uses the one-letter abbreviated commands (e.g., `p` instead of `pick`)
  when generating the interactive rebase script. Especially useful if
  your editor is `vi`, because `r` followed by a letter to replace a
  single letter is much faster than replacing a word.

## Appendix B: Tooling

You can do all the things you need with plain `git`, but there is a lot of tooling that greatly improves the UX and takes out good deal manual handy work from the workflow. However, to understand what these tools do, it can be beneficial to be able to do what they do by hand (although some of them like `magit` have a command log that show you the raw `git` commands).

### git-absorb

When you have new changes to override some of the already applied changes (this often happens from a PR review), this tool can automatically detect the relevant commits and create fixup! commits for the new changes.

<https://github.com/tummychow/git-absorb>

### magit

A bit more complex tool to navigate various git commands. Besides a lot of other features, it allows to easily select "hunks" of changes to more easily create atomic commits from your work tree (an easier to use version of `git add -p`).

Available in emacs, VsCode and possibly elsewhere. A magit inspired CLI tool gex <https://github.com/Piturnah/gex>.

### delta

Rust syntax aware diff.

<https://github.com/dandavison/delta>

### git-stack

A useful tool that automates a lot of manual labor when dealing with PRs that depend on other PRs (i.e. stacked branches).

<https://github.com/gitext-rs/git-stack>

### git-dive

Similar to git blame, but with some improvements.

<https://github.com/gitext-rs/git-dive>
