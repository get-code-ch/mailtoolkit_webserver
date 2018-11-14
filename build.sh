#!/bin/bash

if [ ! -d /data/mail ]; then
    sudo mkdir -p /data/mail
    sudo chown 2222:2222 /data/mail
fi

# rebuild postfix image and run container
docker-compose up -d --build postfix mailtoolkit