FROM node:20-alpine

WORKDIR /app

COPY package.json .
RUN npm install

COPY index.js .

EXPOSE 3000

ENV PORT=3000

CMD ["node", "index.js"]
