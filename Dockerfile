###################
# BUILD FOR AWS DEPLOYMENT
###################

FROM public.ecr.aws/docker/library/node:18-alpine3.20

WORKDIR /usr/src/app

RUN apk upgrade --update-cache --available && \
    apk add openssl && \
    rm -rf /var/cache/apk/*
RUN apk add --no-cache bash
RUN npm install -g pnpm
# Files required by pnpm install
COPY package.json pnpm-lock.yaml ./

RUN pnpm install 
RUN mkdir -p node_modules/.cache && chmod -R 777 node_modules/.cache

COPY . .
RUN pnpm run build

CMD ["pnpm", "run", "start"]