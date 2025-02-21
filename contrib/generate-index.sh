#!/usr/bin/env sh
set -e

PATH_PREFIX=$1

# Define the path you want to redirect to
TARGET_PATH="bark/struct.Wallet.html"

# Create the index.html file with an auto-redirect
cat > "${PATH_PREFIX}/index.html" <<EOF
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

echo "${PATH_PREFIX}/index.html created and redirects to $TARGET_PATH"
