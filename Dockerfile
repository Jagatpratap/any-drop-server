FROM rust:1-slim AS build
WORKDIR /src
COPY server ./server
RUN cd server && cargo build --release

FROM debian:bookworm-slim
COPY --from=build /src/server/target/release/anydrop-server /usr/local/bin/anydrop-server
COPY web /app/web
ENV WEB_DIR=/app/web PORT=8080 DATA_DIR=/data
VOLUME /data
EXPOSE 8080
CMD ["anydrop-server"]
