FROM maven:3.9-eclipse-temurin-17 AS build
ARG TARGETARCH
WORKDIR /build
COPY wonchang/pom.xml ./pom.xml
RUN mvn -B -ntp dependency:go-offline
COPY wonchang/src/ ./src/
RUN mvn -B -ntp -DskipTests package
RUN case "$TARGETARCH" in \
      amd64) sqlite_arch=x86_64 ;; \
      arm64) sqlite_arch=aarch64 ;; \
      *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && mkdir -p /build/native \
    && cd /build/native \
    && jar xf /root/.m2/repository/org/xerial/sqlite-jdbc/3.53.4.0/sqlite-jdbc-3.53.4.0.jar org/sqlite/native/Linux/$sqlite_arch/libsqlitejdbc.so \
    && mv org/sqlite/native/Linux/$sqlite_arch/libsqlitejdbc.so ./libsqlitejdbc.so \
    && chmod 755 libsqlitejdbc.so

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 wonchang \
    && useradd --system --uid 1000 --gid 1000 --home-dir /app --no-create-home wonchang \
    && install -d -o wonchang -g wonchang /app/data /app/.reset-backups
COPY --from=build --chown=wonchang:wonchang /build/target/wonchang-university-1.0.0.jar /app/wonchang.jar
COPY --from=build --chown=wonchang:wonchang /build/native/libsqlitejdbc.so /app/native/libsqlitejdbc.so
COPY --chown=wonchang:wonchang wonchang/reset-supervisor.py /app/reset-supervisor.py
USER wonchang
ENV SERVER_PORT=4102 WONCHANG_DB_PATH=/app/data/wonchang.sqlite \
    JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=/tmp -Dorg.sqlite.lib.path=/app/native -Djava.library.path=/app/native"
EXPOSE 4102
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl --fail --silent --show-error http://127.0.0.1:4102/ >/dev/null || exit 1
ENTRYPOINT ["java", "-jar", "/app/wonchang.jar"]
