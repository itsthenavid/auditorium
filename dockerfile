# syntax=docker/dockerfile:1
FROM python:latest

# Set environment variables for Python
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Set the working directory in the container
WORKDIR /code

# Copy the current directory contents into the container at /code
ADD . /code

# Install system dependencies
RUN apt-get -y update && apt-get -y upgrade
RUN apt-get -y install gcc
RUN apt-get -y install libpq-dev
RUN apt-get -y install gettext
RUN rm -rf /var/lib/apt/lists/*
RUN pip install --upgrade pip
RUN pip install wheel

# Install Python dependencies
RUN pip install -r /code/requirements.txt

# Expose port 8000 to the outside world (:
EXPOSE 8000

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "config.wsgi:application"]
