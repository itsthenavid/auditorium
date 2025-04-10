# Use the official Python runtime image
FROM python:latest

# Create the app directory
RUN mkdir /app
 
# Set the working directory inside the container
WORKDIR /app

# Install system dependencies
RUN apt-get update \
  && apt-get install -y gcc cmake gettext libpq-dev \
  && apt-get clean
 
# Set environment variables 
# Prevents Python from writing pyc files to disk
ENV PYTHONDONTWRITEBYTECODE=1
#Prevents Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1 
 
# Upgrade pip and installing basic dependencies
RUN pip install --upgrade pip 
RUN pip install Wheel
 
# Copy the Django project  and install dependencies
ADD requirements.txt  /app/
 
# run this command to install all dependencies 
RUN pip install --no-cache-dir -r requirements.txt
 
# Copy the Django project to the container
ADD . /app/
 
# Expose the Django port
EXPOSE 8000
 
# Run Django’s development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
