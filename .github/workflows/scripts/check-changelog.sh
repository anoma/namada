#!/bin/bash

check_changelog_added_in_subfolders() {
    current_branch=$(git rev-parse --abbrev-ref HEAD)

    subfolders=("ci" "bug-fixes" "improvements" "miscellaneous" "features" "testing" "docs")

    subfolder_pattern=$(printf "|%s" "${subfolders[@]}")
    subfolder_pattern=${subfolder_pattern:1} # Remove the leading '|'

    added_files=$(git diff --diff-filter=A --name-only "main..$current_branch" | grep "\.changelog/")

    relevant_files=$(echo "$added_files" | grep -E "\.changelog/unreleased/($subfolder_pattern)/")

    if [ -n "$relevant_files" ]; then
        echo "Changelog found: $relevant_files"
    else
        echo "No files were added in the .changelog directory in the specified subfolders."
    fi
}

check_changelog_added_in_subfolders