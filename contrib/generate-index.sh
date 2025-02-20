#!/usr/bin/env sh
set -e

# only makes sense if you use this in a CI environment
if [ -z "$CI_COMMIT_SHA" ]; then
	exit 2
fi

# Define the path you want to redirect to
TARGET_PATH="bark/struct.Wallet.html"

# Create the index.html file with an auto-redirect
cat > /host/data/rustdocs/doc/index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="refresh" content="0;url=$TARGET_PATH">
    <title>Redirecting...</title>
</head>
<body>
    <p>If you are not redirected, <a href="$TARGET_PATH">click here</a>.</p>
    <script>
        window.location.href = "$TARGET_PATH";
    </script>
</body>
</html>
EOF

echo "index.html created and redirects to $TARGET_PATH"
