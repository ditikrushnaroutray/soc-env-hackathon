# Use the official lightweight Python image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all your code into the container
COPY api/ ./api/
COPY baseline/ ./baseline/

# Expose the port FastAPI runs on
EXPOSE 8000

# Start the FastAPI engine
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
