#!/usr/bin/env sh

FILE_NAMES="${1:-}"
if [ -z "$FILE_NAMES" ]; then
  echo "Error: FILE_NAMES argument is required" >&2
  exit 1
fi

if [ -z "${CI_COMMIT_TAG:-}" ]; then
  echo "Error: CI_COMMIT_TAG is not set" >&2
  exit 1
fi

if [ -z "${GITLAB_RELEASE_TOKEN:-}" ]; then
  echo "Error: GITLAB_RELEASE_TOKEN is required" >&2
  exit 1
fi

echo "Checking release for tag ${CI_COMMIT_TAG}"
RESPONSE=$(curl --silent --request GET \
  --header "PRIVATE-TOKEN: $GITLAB_RELEASE_TOKEN" \
  "https://gitlab.com/api/v4/projects/75519706/releases/${CI_COMMIT_TAG}")

if echo "$RESPONSE" | jq -e '.tag_name' > /dev/null; then
  RELEASE_ID=$(echo "$RESPONSE" | jq '.id')
  echo "Release exists: ID $RELEASE_ID"
else
  echo "Creating new release"
  RESPONSE=$(curl --silent --request POST \
	--header "PRIVATE-TOKEN: $GITLAB_RELEASE_TOKEN" \
	--header "Content-Type: application/json" \
	--data '{
	  "name": "'${CI_COMMIT_TAG}'",
	  "tag_name": "'${CI_COMMIT_TAG}'",
	  "description": "Automated release from Woodpecker CI",
	  "milestones": [],
	  "assets": { "links": [] }
	}' \
	"https://gitlab.com/api/v4/projects/75519706/releases")
  echo "Create release response: $RESPONSE"
fi

sleep 2s

ASSET_LINKS=""
for file in ${FILE_NAMES}; do
  if [ -f "$file" ]; then
	FILENAME=$(basename "$file")
	echo "Uploading $FILENAME"
	UPLOAD_RESPONSE=$(curl --silent --request POST \
	  --header "PRIVATE-TOKEN: $GITLAB_RELEASE_TOKEN" \
	  --form "file=@$file" \
	  "https://gitlab.com/api/v4/projects/75519706/uploads")
	echo "Upload response $UPLOAD_RESPONSE"

	UPLOAD_URL=$(echo "$UPLOAD_RESPONSE" | jq -r '.url')
	echo "Upload $UPLOAD_URL"
	if [ "$UPLOAD_URL" != "null" ]; then
	  # Add to links array
	  LINK_JSON=$(printf '{"name": "%s", "url": "https://gitlab.com/-/project/75519706%s", "link_type": "other"}' "$FILENAME" "$UPLOAD_URL")
	  echo "Upload json link $LINK_JSON"
	  if [ -z "$ASSET_LINKS" ]; then
		ASSET_LINKS="[$LINK_JSON"
	  else
		ASSET_LINKS="$ASSET_LINKS, $LINK_JSON"
	  fi
	fi
  else
	echo "Warning: $file not found"
  fi
done
ASSET_LINKS="$ASSET_LINKS]"

echo "Uploaded assets $ASSET_LINKS"
if [ "$ASSET_LINKS" != "[]" ] && [ "$ASSET_LINKS" != "null" ]; then
  echo "Linking $(echo "$ASSET_LINKS" | jq 'length') asset(s) to release..."

  EXISTING_RESPONSE=$(curl --silent --fail --show-error \
    --header "PRIVATE-TOKEN: $GITLAB_RELEASE_TOKEN" \
    "https://gitlab.com/api/v4/projects/75519706/releases/${CI_COMMIT_TAG}")

  EXISTING_LINKS=$(echo "$EXISTING_RESPONSE" | jq '.assets.links // []')
  EXISTING_URLS=$(echo "$EXISTING_LINKS" | jq -r '.[].url')

  echo "$ASSET_LINKS" | jq -c '.[]' | while read -r asset; do
    NAME=$(echo "$asset" | jq -r '.name')
    URL=$(echo "$asset" | jq -r '.url')
    LINK_TYPE=$(echo "$asset" | jq -r '.link_type // "other"')

    # Skip if URL already exists
    if echo "$EXISTING_URLS" | grep -q "^$URL$"; then
      echo "Link already exists: $NAME ($URL)"
      continue
    fi

    echo "Creating release link: $NAME -> $URL"

    RESPONSE=$(curl --silent --fail-with-body \
      --request POST \
      --header "PRIVATE-TOKEN: $GITLAB_RELEASE_TOKEN" \
      --header "Content-Type: application/json" \
      --data "{
        \"name\": $(printf '%s' "$NAME" | jq -R .),
        \"url\": $(printf '%s' "$URL" | jq -R .),
        \"link_type\": $(printf '%s' "$LINK_TYPE" | jq -R .)
      }" \
      "https://gitlab.com/api/v4/projects/75519706/releases/${CI_COMMIT_TAG}/assets/links")

    if [ $? -eq 0 ]; then
      echo "Successfully linked: $NAME"
    else
      echo "Failed to link: $NAME"
      echo "Response: $RESPONSE"
    fi
  done

  echo "Release assets updated: https://gitlab.com/ark-bitcoin/bark/-/releases/${CI_COMMIT_TAG}"
else
  echo "No assets to link."
fi

echo "GitLab release: https://gitlab.com/ark-bitcoin/bark/-/releases/${CI_COMMIT_TAG}"
