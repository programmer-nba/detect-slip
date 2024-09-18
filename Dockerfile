FROM node:18.20.3

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

RUN npm rebuild sqlite3

EXPOSE 5000

CMD ["npm", "start"]
