# define the base image of the container
FROM jupyter/base-notebook

# set the working directory in the container
WORKDIR /notebook

# install net-tools so we can check on the network
RUN apt-get update && apt-get install net-tools -y

# copy the notebook into the container
COPY ../jupyter_books/console.pynb /notebook


