# Use the official lightweight Python image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# CRITICAL: The judges' bot looks for this file immediately.
COPY openenv.yaml .

# Copy root entry point
COPY app.py .

# Copy all package code (includes scenarios)
COPY soc_analyst_env/ ./soc_analyst_env/

# Copy inference script
COPY inference.py .

# Copy validation script
COPY validate-submission.sh .
RUN chmod +x validate-submission.sh

# Expose the port FastAPI runs on
EXPOSE 7860

# Start the FastAPI server
CMD ["uvicorn", "soc_analyst_env.server.app:app", "--host", "0.0.0.0", "--port", "7860"]