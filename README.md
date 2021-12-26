# mtls4j | Twuni

mtls4j encourages mTLS adoption by providing a convenient and simple
way to seed an [`HttpClient`][1] with the necessary configuration for
successfully making a request to a service that requires a TLS client
certificate, and/or which presents a certificate issued by a CA not
in the system default trust store.

## Prerequisites

This package is distributed via the [Twuni Software Foundation repository][3].
Add it to your project's **pom.xml** or equivalent with the URL:

    https://twuni.org/maven/repository/libs-release

For example, in a Maven project, add the following to the `<repositories>` block of **pom.xml**:

```xml
<repository>
  <id>twuni-releases</id>
  <url>https://twuni.org/maven/repository/libs-release</url>
</repository>
```

## Installing

If you are using Maven, add the following section to your POM's `<dependencies>` block:

```xml
<dependency>
  <groupId>dev.twuni</groupId>
  <artifactId>mtls4j</artifactId>
  <version>0.0.2</version>
</dependency>
```

For other Maven-compatible package managers, use the spec `dev.twuni:mtls4j:0.0.2`.

## Usage

For detailed usage information, consult the [API Reference][2].

[1]: https://docs.oracle.com/en/java/javase/17/docs/api/java.net.http/java/net/http/HttpClient.html
[2]: https://twuni.github.io/mtls4j/apidocs
[3]: https://twuni.org/maven/repository/libs-release/
