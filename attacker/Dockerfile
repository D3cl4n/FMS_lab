# define the base image
FROM python:3.10-slim

# set the working directory in the container
WORKDIR /attacker

# copy requirements.txt and install python modules
COPY requirements.txt /attacker
RUN pip install -r requirements.txt

# install net-tools so we can run check on the network
RUN apt-get update && apt-get install net-tools -y

# copy the python scripts into the container
COPY sniffer.py /attacker
