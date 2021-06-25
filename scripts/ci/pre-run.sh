# script used only during CI execution.

SKIP=${1:-true}

# we don't want to skip pipeline execution if event is push
if [[ "push" == "$DRONE_BUILD_EVENT" ]]; then
  exit 0
fi

if [ "$SKIP" = false ] ; then 
  exit 0
fi


COMMIT_MESSAGE=$(git show -s --format=%B ${DRONE_COMMIT_SHA})
CHECK="[ci]"

case "$COMMIT_MESSAGE" in 
  *"$CHECK"*)
    echo "Skipping pipeline."
    exit 78
    ;;
esac