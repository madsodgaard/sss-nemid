FROM swift:5.3-focal
COPY Sources/ Sources/
COPY Tests/ Tests/
COPY Package.swift Package.swift
RUN apt update -y
RUN apt install -y libxml2-dev
CMD ["swift", "test", "--enable-test-discovery"]
