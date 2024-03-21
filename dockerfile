# syntax=docker/dockerfile:1
FROM python:latest

# Set environment variables for Python
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Set the working directory in the container
WORKDIR /code

# Copy the current directory contents into the container at /app
COPY . /code

# Install system dependencies
RUN apt-get -y update && apt-get -y upgrade && 
    apt-get -y install \
    apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    gettext \≈
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8000 to the outside world
EXPOSE 8000

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "your_project_name.wsgi:application"]

