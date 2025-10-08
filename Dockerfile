FROM node:18-alpine

# Create app directory
WORKDIR /app

# Copy only package files first for caching
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy remaining source files
COPY . .

# Expose the port the app runs on
EXPOSE 5001

# Start the application
CMD ["npm", "start"]
