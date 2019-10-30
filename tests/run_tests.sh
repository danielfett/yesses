#!/bin/bash

cd tests/ || exit 1
docker-compose build
docker-compose run test_container
echo -e "\nReturn status: ${?}\n"
docker-compose down