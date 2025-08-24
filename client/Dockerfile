# define the base image of the container
FROM python:3.10-slim

# set the working directory in the container
WORKDIR /client

# copy requirements.txt and install python modules
COPY requirements.txt /client
RUN pip install -r requirements.txt

# install net-tools so we can run check on the network
RUN apt-get update && apt-get install net-tools -y

# copy python script into the container
COPY client.py /client

# execute the client python script
CMD ["tail", "-f", "/dev/null"]
