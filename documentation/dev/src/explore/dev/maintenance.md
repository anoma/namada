# Maintainer's handbook

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

## Appendix: Useful git configuration settings

See also the [developer recommended git configuration](./git.md#appendix-a-useful-git-configuration-settings).

- `merge.log = 100`

  Include the shortlog of the branch being merged in the merge commit,
  which is helpful for reading history at the first-parent level. Very
  few branches will be over 100 commits; you can decide whether to use a
  higher `--log` option if you merge one of these. 100 is already quite
  a ways on the high side.

- `alias.reroll = rebase --interactive --keep-base`

  Easily reroll a topic branch with this alias, just by specifying
  `main` or similar as the upstream. Helps to keep rerolling (editing
  a branch) from rebasing proper (moving it to a different base point)
  conceptually separate. Note that `--rebase-merges` is not in the
  alias, and will have to be specified if you are rerolling merges (very
  advanced!)
