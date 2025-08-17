# set the base image
FROM python:3.10-slim

# set the working dir for the container
WORKDIR /access_point

# install net-tools so we can run check on the network
RUN apt-get update && apt-get install net-tools -y

# copy the access_point script to the container
COPY ap.py /access_point
