#!/bin/bash

if [ -d $APD_DATADIR ]
then
  echo "The directory already exists"
  echo "The configuration will be updated"
  aspd set-config
else
  echo "A new aspd will be created"
  aspd create
fi

# Running the actual command
exec "$@"
