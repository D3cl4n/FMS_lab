# define the base image of the container
FROM jupyter/base-notebook:python-3.11

# set the working directory in the container
WORKDIR /home/jovyan/work

# copy requirements.txt and install python modules
COPY requirements.txt /home/jovyan/work
RUN pip install -r requirements.txt

# copy the notebook into the container
COPY fms_interface.ipynb /home/jovyan/work

# document the port exposed on the container
EXPOSE 8888

# run Jupyter Notebook
# use 0.0.0.0 to bind to host not just container
# no browser so jupyter doesn't launch browser in container
CMD ["jupyter", "notebook", "--ip=0.0.0.0", "--port=8888", "--allow-root", "--no-browser", "--NotebookApp.token=lab"]
