# Use the official Debian image
FROM debian:bullseye-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install Python and pip
RUN apt-get update && apt-get install -y python3 python3-pip

# Install any needed packages specified in requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Make the stahlta binary executable
RUN chmod +x binaries/stahlta

# Run the stahlta binary when the container launches
CMD ["./binaries/stahlta"]