#!/bin/sh
# VenPK Android - Gradle Wrapper
# This script downloads and executes the Gradle wrapper if needed

set -e

APP_NAME="VenPK-Android"
APP_HOME=$(dirname "$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")")
GRADLE_WRAPPER_JAR="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"

# Check for JAVA_HOME
if [ -n "$JAVA_HOME" ]; then
    JAVACMD="$JAVA_HOME/bin/java"
else
    JAVACMD="java"
fi

if ! command -v "$JAVACMD" >/dev/null 2>&1; then
    echo "ERROR: Java not found. Please set JAVA_HOME."
    exit 1
fi

# Execute Gradle
exec "$JAVACMD" -Dorg.gradle.appname="$APP_NAME" -classpath "$GRADLE_WRAPPER_JAR" org.gradle.wrapper.GradleWrapperMain "$@"
