FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* /app/
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY . /app

EXPOSE 5173
CMD ["npm", "run", "dev"]
