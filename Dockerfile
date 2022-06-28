FROM ghcr.io/james-chf/devchain-container:sha-8e60590
COPY target/debug/anoma /usr/local/bin
COPY target/debug/anomac /usr/local/bin
COPY target/debug/anoman /usr/local/bin
COPY target/debug/anomaw /usr/local/bin