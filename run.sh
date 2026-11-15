#!/bin/sh
# Start AnyDrop on this machine. Scan the QR code it prints with your phone.
cd "$(dirname "$0")" && bun install --silent && exec bun run start
