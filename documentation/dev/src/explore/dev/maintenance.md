# Maintenance

If you do not intend to merge topics as a maintainer of the repository,
but just write them, you should only have to read this section, though
the reasoning behind certain choices is shortened.

Advice about structuring branches is low-stakes (for the purposes of
the contributor's handbook section) because it can be changed easily.
Advice about making commits is more important, because you are the
person most knowledgable about your topic. Despite this, the sections
are organized in chronological order (over the lifecycle of a topic)
rather than order of importance, to create a narrative.

## The official branches

- `latest`: a convenience branch which always points to the latest
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

## Creating a new topic

In general, when starting a new topic, base its branch on the latest
minor release tag (`vX.Y.0`). Include your name in the branch name to
indicate that you own it, e.g. `ray/topic-1`. (Git branch names are
paths, with their components separated by `/`; in many repositories,
the "top level" (branch names without a `/` belongs to the repository
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

# Anoma maintainer's handbook

There are two types of branches in git repositories: topic branches,
where actual work happens, and integration branches, where work is
integrated into a final product. A maintainer is anyone wearing the hat
of work on integration branches. Someone with a contributor hat on just
needs to present the maintainer with topic branches.

Contributors should follow good style, but their mistakes can be
corrected. Maintainer mistakes are often permanent, so the maintainer
hat should be worn conservatively.

## Version numbering

The release engineering of a piece of software dictates the practice of
maintenance work on its integration branches. As an example to use for
this document, a simple version numbering scheme might work as follows:

`major.minor.patch`, where:

- `major` is a broad identifier for the software as a whole. Major
  version 1 and major version 2 are almost different pieces of software.
  Everything is broken between them. Major version 0 is explicitly
  incomplete work. Ideally, only major version numbers 0 and 1 are ever
  used.

- `minor` is a regular feature release. This is recognizably the same
  piece of software, but new and (hopefully) improved. Either nothing
  breaks, or it breaks on a carefully managed deprecation schedule.
  During major version 0, probably things break more frequently on minor
  releases, because the software is explicitly incomplete work.

- `patch` is an ad-hoc release made between minor releases. Perhaps a
  regression was detected and fixed, or functionality needs to be
  released ahead of the minor release schedule. This is the minor
  release plus some other things, which are all things which are also
  going into the next minor release.

## The minor release trunk line

The general case of integration proceeds from minor release to minor
release (major release 1.0.0 counts as a minor release for this purpose,
and we are pretending we never to have to release 2.0.0, which would
involve some additional concerns outside the scope of this document).

The integration branch from which minor releases are made is often
called `master`, one of Git's myriad tape-deck metaphors. Because
tape-deck metaphors are somewhat unclear, we call it by the more
descriptive name `release`. Merging a topic here is the act of including
it in the next minor release.

An important thing to keep in mind is that the parent order of a merge
commit matters in Git. The first parent is the (integration, usually)
branch being merged into, while the second (or further) parent(s) are
the branch(es) being merged into it. The `--first-parent` option can be
passed to many commands to follow the first parent log specifically,
which provides precisely this minor release construction log without the
detailed logs of each topic branch.

This branch is not a prerelease version or similar; it is a minor
release under construction. Its log details the construction of minor
releases. An arbitrary point where this branch was at some point is not
a sensible base point to apply topic branches to. If the latest minor
release is `v1.7.0`, and 30 topics have been merged to `release` (i.e.,
added to the upcoming `v1.8.0`), the ordinary base point for a new topic
(assuming no other considerations, discussed below, apply) is `v1.7.0`.

For convenience, we should keep a branch pointer called `base` pointed
at the most recent `vX.Y.0` release tag, using this as the default view
on e.g. Github. Pull requests could be opened against `base`, but this
would cause milestones to show as 0 perpetually; making them against
`release` preserves the useful issue tracker features.

## Merging specifics

Merge the branch with `merge --log` (or use a `.gitconfig` setting,
detailed below) to include the shortlog in the merge message. It's
a bit nicer if you check out the branch locally rather than merging the
remote-tracking branch, because the message is shorter. Put pull request
numbers in the first line (e.g., change `Merge branch 'alice/topic-1'`
to `Merge branch 'alice/topic-1' (#123)`). Ideally, write a paragraph
between the first line and the shortlog describing the branch.

## Graduating topics

Naturally, topics do not spring from the keyboard fully formed and QAed,
ready to be instantly merged (which, remember, means "included in the
upcoming minor release"). It is helpful to have one (or more)
integration branch(es) to which topics are merged more promiscuously,
without this meaning their definite inclusion as-is in the next minor
release.

Git itself uses two, `seen` and `next`, roughly meaning "the maintainer
has seen this" and "the maintainer is considering this for inclusion".
We can assume one (the equivalent of `next`) for the purposes of this
document; because `next` is a somewhat ambiguous traditional name, we
call it `draft`.

Anyone can, of course, have as many personal integration branches as
they wish, to which they can merge whatever topics they want; an
official `draft` just means someone actually maintaining the upcoming
minor release is doing that.

Ordinarily, a topic can come in, be reviewed and possibly changed, be
merged into `draft`, and eventually merged into `release` after due
diligence (e.g., QA deployments from `draft`). It's possible that topics
may be merged, or other changes like changelog batches made, on
`release` which are not on `draft`; the maintainer can merge `release`
into `draft` occasionally if this happens.

`draft` and similar branches are temporary; they can be reset to the
minor version tag on each minor version. A branch like `draft` is more of
a scratch area than an integration branch, and its history is not
valuable.

## Maintenance branches

Recall that a patch release, e.g. `v1.7.1`, is a minor release
(`v1.7.0`) plus some things which are destined for the next minor
release (e.g., `v1.8.0`).

If we assume that each series of maintenance releases includes
everything from the previous (e.g., `v1.7.2` is a superset of `v1.7.1`),
then this naturally suggests a maintenance integration branch (this can
be temporary, e.g. `maint`, or parameterized by minor release, e.g.
`maint-1.7`) starting from the minor release. Patch release tags can be
made on this integration branch.

Changelog updates should be cherry-picked back to `release` so the
mainline changelog accurately reflects which topics were released when,
but other than this clerical work, the integration branches do not
interact.

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

## Considerations on textual conflicts

"Conflict" is a poorly chosen word - three-way merge is just a very
simple algorithm working on lines of text, which cannot possibly resolve
every case without human intervention. Unfortunately, the combination of
this poorly chosen word and the fact that version control systems stop
the world when a conflict is encountered make conflicts feel like an
error, even to people who intellectually know otherwise.

Conflict diffs are contained in merge commits, and are an important part
of the log; branches should not be wantonly rebased to avoid them,
because this destroys useful information. Maintainers should make use of
`rerere` to store conflict resolutions to avoid having to make the same
ones multiple times. If someone else has resolved a conflict, and you
have that merge commit available, you can use `rerere-train.sh`
available in the git repository for git under `contrib/` to add it to
your `rerere` database, and repeat the resolution.

If a maintainer lacks the context to resolve a conflict, and wants the
contributor to do it, they should ask the contributor to perform the
merge. If the contributor performed the merge in the correct direction
(integration branch left, topic branch right), the topic can be merged
with `--ff-only`; if the contributor performed it in the wrong direction
(merged `release` into their branch), the merge commit can be used with
`rerere-train.sh` to construct the correct one.

## Fast-forward restrictions

By convention, the final integration branches (e.g., `master`/`release`,
`maint`) are always fast-forward only (and others such as `next`/`draft`
will be as well, between resets). However, fast-forward is not a
sufficient condition, because it merely checks that the previous head is
an ancestor of the proposed new head. Absent the ability to set
repository hooks on the remote, the maintainer must take care to
preserve the first-parent history by only having merges of topic
branches into the integration branch. It is quite possible to push a
backwards merge that hides the entire history of `master`, which is
still a valid fast forward! For example, in the git repository for git:

```
% git checkout -b bad e83c516331
Switched to a new branch 'bad'
% git log
commit e83c5163316f89bfbde7d9ab23ca2e25604af290 (HEAD -> bad)
Author: Linus Torvalds <torvalds@ppc970.osdl.org>
Date:   Thu Apr 7 15:13:13 2005 -0700

    Initial revision of "git", the information manager from hell
% git merge master
[long output snipped]
% git log --first-parent
commit 5dae9cc7fe29532ac939790d03c5b28ab42e7ac0 (HEAD -> bad)
Merge: e83c516331 5d01301f2b
Author: Raymond E. Pasco <ray@ameretat.dev>
Date:   Thu Feb 3 06:59:26 2022 -0500

    Merge branch 'master' into bad

commit e83c5163316f89bfbde7d9ab23ca2e25604af290
Author: Linus Torvalds <torvalds@linux-foundation.org>
Date:   Thu Apr 7 15:13:13 2005 -0700

    Initial revision of "git", the information manager from hell
% git checkout master
Switched to branch 'master'
Your branch is up to date with 'junio/master'.
% git merge --ff-only bad
Updating 5d01301f2b..5dae9cc7fe
Fast-forward
```

If I were Junio Hamano, I could overwrite the official upstream `master`
with this, which is a valid fast-forward, and make 17 years of history
significantly less useful for everyone forever.

Under fast-forward restrictions, merges can only be backed out using
`revert`s. (Ideally, merges are made conservatively to such branches,
after QA, so this does not have to happen!) A `revert` of a merge (made
with `revert -m 1` to specify that the first parent is what should be
reverted to) does not undo the merge, which is still in the history,
only the changes it introduced. When the topic branch is corrected, it
cannot merely be merged again, because graph walking will identify the
merge base as the last unchanged commit on the topic branch. It can be
merged again if every commit is different, which can be done with
`rebase --no-ff` to force rewriting of every commit on the topic. The
presence of the reverted branch may confuse `bisect` in some instances;
`bisect skip` can be used to ignore this part of history if this
happens.

## Release commits and tags

A release commit contains the bumping of the version number and whatever
ancillary changes are a direct result of this (for example, lockfiles
will likely be updated, and the changelog will move items into the new
version's heading).

This commit is the commit which is tagged. A signed tag should be used
here. The messages for both the commit and tag can be very simple -
e.g., just "Anoma 0.4.0" for Anoma 0.4.0. By standard convention,
version tags start with `v`, so the above release is tagged `v0.4.0`.

There are few complicated considerations here, but this is the most
permanent and irrevocable operation a maintainer can perform, so it's
worth triple-checking to make sure everything is correct.

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
* commit cccfb78 (HEAD, tag: v0.1.0, release, latest, draft)
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
* cccfb78 (tag: v0.1.0, release, latest) version 0.1.0
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
* cccfb78 (tag: v0.1.0, latest) version 0.1.0
* 291d127 prehistory
```

## Appendix: Useful git configuration settings

- `merge.ff = false` in combination with `alias.ff = merge --ff-only`

  Rather than having to deal with git's somewhat troublesome
  "fast-forward if possible, else make a merge commit" default behavior,
  set `merge` to always make a merge commit, and use the `ff` alias to
  fast-forward when desired.

- `merge.log = 100`

  Include the shortlog of the branch being merged in the merge commit,
  which is helpful for reading history at the first-parent level. Very
  few branches will be over 100 commits; you can decide whether to use a
  higher `--log` option if you merge one of these. 100 is already quite
  a ways on the high side.

- `alias.reroll = rebase --interactive --keep-base`

  Easily reroll a topic branch with this alias, just by specifying
  `master` or similar as the upstream. Helps to keep rerolling (editing
  a branch) from rebasing proper (moving it to a different base point)
  conceptually separate. Note that `--rebase-merges` is not in the
  alias, and will have to be specified if you are rerolling merges (very
  advanced!)

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
