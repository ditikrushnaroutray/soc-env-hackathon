# Use the official lightweight Python image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all your code into the container
COPY soc_analyst_env/ ./soc_analyst_env/
COPY inference.py .

# Expose the port FastAPI runs on
EXPOSE 8000

# Start the FastAPI server using the OpenEnv packaged app.
CMD ["uvicorn", "soc_analyst_env.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
