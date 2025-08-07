#!/bin/bash

set -e

ACTION=${1:-start}
COUNT=${2:-5}
TARGET_URL=${3:-"https://verrado.ezlinksgolf.com"}

echo "Action: $ACTION"
echo "Container Count: $COUNT"
echo "Target URL: $TARGET_URL"

case $ACTION in
"build")
  echo "Building Docker images..."
  docker build -t doscrape-token-collector .
  echo "Build completed"
  ;;

"start")
  mkdir -p results
  echo "Cleaning up existing containers..."
  docker stop $(docker ps -q --filter "name=token-collector-") 2>/dev/null || true
  docker rm $(docker ps -aq --filter "name=token-collector-") 2>/dev/null || true

  for i in $(seq 1 $COUNT); do
    echo "Starting container ($i)"
    docker run -d \
      --name "token-collector-$i" \
      --env "TARGET_URL=$TARGET_URL" \
      --env CONTAINER_ID=$i \
      --volume "$(pwd)/results:/app/results" \
      doscrape-token-collector
  done

  echo "Started $COUNT containers"
  ;;

"stop")
  echo "Stopping all containers..."
  docker stop $(docker ps -q --filter "name=token-collector-") 2>/dev/null || true
  docker rm $(docker ps -aq --filter "name=token-collector-") 2>/dev/null || true
  echo "All containers stopped"
  ;;

*)
  echo "Unknown action: $ACTION"
  echo "Usage: $0 [start|stop|build] [count]"
  exit 1
  ;;
esac
