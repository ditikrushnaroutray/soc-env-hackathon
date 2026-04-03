# Use the official lightweight Python image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# CRITICAL FIX: The judges' bot looks for this file immediately.
COPY openenv.yaml .

# Copy all your code into the container
COPY soc_analyst_env/ ./soc_analyst_env/
COPY inference.py .

# Expose the port FastAPI runs on
EXPOSE 8000

# Start the FastAPI server using the OpenEnv packaged app.
<<<<<<< HEAD
=======
ENV ENABLE_WEB_INTERFACE=true
>>>>>>> df617397fa817e65274169249a501497bca0c76d
CMD ["uvicorn", "soc_analyst_env.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
