# define the base image of the container
FROM jupyter/base-notebook

# set the working directory in the container
WORKDIR /notebook

# copy requirements.txt and install python modules
COPY requirements.txt /notebook
RUN pip install -r requirements.txt

# copy the notebook into the container
COPY fms_notebook.ipynb /notebook

# document the port exposed on the container
EXPOSE 8888

# run Jupyter Notebook
CMD ["jupyter", "notebook", "--ip=127.0.0.1", "--port=8888"]
