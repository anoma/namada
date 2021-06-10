# script used only during CI execution.

git config user.email "gianmarco@heliax.dev"
git config user.name "Drone CI"

if [ -z "$(git status ':/*.wasm' --porcelain)" ]; then 
    echo "No changes to commit."
    exit 0
fi

REMOTE=$(git remote get-url origin | cut -c 9-)
PUSH_URL="https://${GITHUB_TOKEN}@${REMOTE}"

git fetch --all
git checkout $DRONE_SOURCE_BRANCH

if [ $? -ne 0 ]; then
    echo "Can't checkout $DRONE_SOURCE_BRANCH."
    exit 1
fi

git remote set-url origin $PUSH_URL

git add ':/*.wasm'
git status
# git commit -m "[ci]: update wasm"

# git push

exit $?