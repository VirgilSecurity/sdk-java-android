# Virgil Core SDK & Crypto Stack Java/Android

[![Build Status](https://api.travis-ci.org/VirgilSecurity/virgil-sdk-java-android.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-sdk-java-android)
[![Maven](https://img.shields.io/maven-central/v/com.virgilsecurity.sdk/sdk.svg)](https://search.maven.org/artifact/com.virgilsecurity.sdk/sdk)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [SDK Features](#sdk-features) | [Crypto Library Purposes](#crypto-library-purposes) | [Installation](#installation) | [Configure SDK](#configure-sdk) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

The Virgil Core SDK allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

## SDK Features
- Communicate with [Virgil Cards Service](https://developer.virgilsecurity.com/docs/platform/api-reference/cards-service/)
- Manage users' public keys
- Encrypt, sign, decrypt and verify data
- Store private keys in secure local storage
- Use Virgil [Crypto Library](https://github.com/VirgilSecurity/virgil-crypto-javascript)
- Use your own crypto library

## Crypto Library Purposes
* Asymmetric Key Generation
* Encryption/Decryption of data and streams
* Generation/Verification of digital signatures
* PFS (Perfect Forward Secrecy)
* **Post quantum algorithms support**. [Round5](https://round5.org/) (ecnryption) and [Falcon](https://falcon-sign.info/) (signature) 

## Installation

The Virgil Core SDK is provided as set of packages named *com.virgilsecurity.sdk*. Packages are distributed via Maven repository.  Also in this guide, you find one more package - Virgil Crypto Library that is used by the SDK to perform cryptographic operations.

### Target

* Java 7+.
* Android API 16+.

### Prerequisites

* Java Development Kit (JDK) 7+
* Maven 3+

### Installing the package

You can easily add SDK dependency to your project, just follow the examples below:

#### Maven

Use this packages for Java projects:

```
<dependencies>
    <dependency>
        <groupId>com.virgilsecurity.sdk</groupId>
        <artifactId>sdk</artifactId>
        <version><latest-version></version>
    </dependency>
</dependencies>
```

#### Gradle

Add jcenter() repository if missing:

```
repositories {
    jcenter()
}
```

Use this packages for Android projects:

```
    implementation "com.virgilsecurity.sdk:sdk-android:<latest-version>"
```

The **\<latest-version>** of the SDK can be found in the [Maven Central Repository](https://mvnrepository.com/artifact/com.virgilsecurity.sdk/sdk) or in the header of current readme.

## Configure SDK

This section contains guides on how to set up Virgil Core SDK modules for authenticating users, managing Virgil Cards and storing private keys.

### Set up authentication

Set up user authentication with tokens that are based on the [JSON Web Token standard](https://jwt.io/) with some Virgil modifications.

In order to make calls to Virgil Services (for example, to publish user's Card on Virgil Cards Service), you need to have a JSON Web Token ("JWT") that contains the user's `identity`, which is a string that uniquely identifies each user in your application.

Credentials that you'll need:

|Parameter|Description|
|--- |--- |
|App ID|ID of your Application at [Virgil Dashboard](https://dashboard.virgilsecurity.com)|
|App Key ID|A unique string value that identifies your account at the Virgil developer portal|
|App Key|A Private Key that is used to sign API calls to Virgil Services. For security, you will only be shown the App Key when the key is created. Don't forget to save it in a secure location for the next step|

#### Set up JWT provider on Client side

Use these lines of code to specify which JWT generation source you prefer to use in your project:

```java
// Get generated token from server-side
final String authenticatedQueryToServerSide =
        "eyJraWQiOiI3MGI0NDdlMzIxZjNhMGZkIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIn0.eyJleHAiOjE1MTg2OTg5MTcsImlzcyI6InZpcmdpbC1iZTAwZTEwZTRlMWY0YmY1OGY5YjRkYzg1ZDc5Yzc3YSIsInN1YiI6ImlkZW50aXR5LUFsaWNlIiwiaWF0IjoxNTE4NjEyNTE3fQ.MFEwDQYJYIZIAWUDBAIDBQAEQP4Yo3yjmt8WWJ5mqs3Yrqc_VzG6nBtrW2KIjP-kxiIJL_7Wv0pqty7PDbDoGhkX8CJa6UOdyn3rBWRvMK7p7Ak";

// Setup AccessTokenProvider
CallbackJwtProvider.GetTokenCallback getTokenCallback = new CallbackJwtProvider.GetTokenCallback() {

        @Override
        public String onGetToken(TokenContext tokenContext) {
                return authenticatedQueryToServerSide;
        }
};
// initialize JWT provider
AccessTokenProvider accessTokenProvider =
        new CallbackJwtProvider(getTokenCallback);
```

#### Generate JWT on Server side

Next, you'll need to set up the `JwtGenerator` and generate a JWT using the Virgil SDK.

Here is an example of how to generate a JWT:

```java
// App Key (you got this Key at Virgil Dashboard)
String appKeyBase64 = "MC4CAQAwBQYDK2VwBCIEINlK4BhgsijAbNmUqU6us0ZU9MGi+HxdYCA6TdZeHjR4";
byte[] appKeyData = ConvertionUtils.base64ToBytes(appKeyBase64);

// Crypto library imports a private key into a necessary format
VirgilCrypto crypto = new VirgilCrypto();
PrivateKey appKey = crypto.importPrivateKey(appKeyData);

// initialize accessTokenSigner that signs users JWTs
AccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();

// use your App Credentials you got at Virgil Dashboard:
String appId = "be00e10e4e1f4bf58f9b4dc85d79c77a"; // App ID
String appKeyId = "70b447e321f3a0fd"; // App Key ID
TimeSpan ttl = TimeSpan.fromTime(1, TimeUnit.HOURS); // 1 hour (JWT's lifetime)

// setup JWT generator with necessary parameters:
JwtGenerator jwtGenerator = new JwtGenerator(appId, appKey, appKeyId, ttl, accessTokenSigner);

// generate JWT for a user
// remember that you must provide each user with his unique JWT
// each JWT contains unique user's identity (in this case - Alice)
// identity can be any value: name, email, some id etc.
String identity = "Alice";
Jwt aliceJwt = jwtGenerator.generateToken(identity);

// as result you get users JWT, it looks like this: "eyJraWQiOiI3MGI0NDdlMzIxZjNhMGZkIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIn0.eyJleHAiOjE1MTg2OTg5MTcsImlzcyI6InZpcmdpbC1iZTAwZTEwZTRlMWY0YmY1OGY5YjRkYzg1ZDc5Yzc3YSIsInN1YiI6ImlkZW50aXR5LUFsaWNlIiwiaWF0IjoxNTE4NjEyNTE3fQ.MFEwDQYJYIZIAWUDBAIDBQAEQP4Yo3yjmt8WWJ5mqs3Yrqc_VzG6nBtrW2KIjP-kxiIJL_7Wv0pqty7PDbDoGhkX8CJa6UOdyn3rBWRvMK7p7Ak"
// you can provide users with JWT at registration or authorization steps
// Send a JWT to client-side
String jwtString = aliceJwt.stringRepresentation();
```

For this subsection we've created a sample backend that demonstrates how you can set up your backend to generate the JWTs. To set up and run the sample backend locally, head over to your GitHub repo of choice:

[Node.js](https://github.com/VirgilSecurity/sample-backend-nodejs) | [Golang](https://github.com/VirgilSecurity/sample-backend-go) | [PHP](https://github.com/VirgilSecurity/sample-backend-php) | [Java](https://github.com/VirgilSecurity/sample-backend-java) | [Python](https://github.com/VirgilSecurity/virgil-sdk-python/tree/master#sample-backend-for-jwt-generation)
 and follow the instructions in README.
 
### Set up Card Verifier

Virgil Card Verifier helps you automatically verify signatures of a user's Card, for example when you get a Card from Virgil Cards Service.

By default, `VirgilCardVerifier` verifies only two signatures - those of a Card owner and Virgil Cards Service.

Set up `VirgilCardVerifier` with the following lines of code:

```java
// initialize Crypto library
CardCrypto cardCrypto = new VirgilCardCrypto();

VerifierCredentials yourBackendVerifierCredentials =
        new VerifierCredentials("YOUR_BACKEND",
                ConvertionUtils.base64ToBytes(PUBLIC_KEY_STR));

Whitelist yourBackendWhiteList =
        new Whitelist(Arrays.asList(yourBackendVerifierCredentials));

CardVerifier cardVerifier = new VirgilCardVerifier(cardCrypto,
        Arrays.asList(yourBackendWhiteList));
```

### Set up Card Manager

This subsection shows how to set up a Card Manager module to help you manage users' public keys.

With Card Manager you can:
- specify an access Token (JWT) Provider.
- specify a Card Verifier used to verify signatures of your users, your App Server, Virgil Services (optional).

Use the following lines of code to set up the Card Manager:

```java
// initialize cardManager and specify accessTokenProvider, cardVerifier
CardManager cardManager = new CardManager(cardCrypto, accessTokenProvider, cardVerifier);
```

### Set up Key Storage for private keys

This subsection shows how to set up a `VSSKeyStorage` using Virgil SDK in order to save private keys after their generation.

Here is an example of how to set up the `VSSKeyStorage` class:

```java
// initialize Crypto library
VirgilCrypto crypto = new VirgilCrypto();
// Generate a private key
VirgilKeyPair keyPair = crypto.generateKeys();
VirgilPrivateKey privateKey = keyPair.getPrivateKey();

// Setup PrivateKeyStorage
VirgilPrivateKeyExporter privateKeyExporter = new VirgilPrivateKeyExporter(crypto);
KeyStorage keyStorage = new JsonFileKeyStorage();
PrivateKeyStorage privateKeyStorage = new PrivateKeyStorage(privateKeyExporter, keyStorage);

// Store a private key with a name, for example Alice
privateKeyStorage.store(privateKey, "Alice", null);

// To load Alice private key use the following code lines:
Tuple<PrivateKey, Map<String, String>> privateKeyEntry = privateKeyStorage.load("Alice");

// Delete a private key
privateKeyStorage.delete("Alice");
```

## Usage Examples

Before you start practicing with the usage examples, make sure that the SDK is configured. See the [Configure SDK](#configure-sdk) section for more information.

### Generate and publish Virgil Cards at Cards Service

Use the following lines of code to create a user's Card with a public key inside and publish it at Virgil Cards Service:

```java
import com.virgilsecurity.crypto.VirgilCrypto;

VirgilCrypto crypto = new VirgilCrypto();

// generate a key pair
VirgilKeyPair keyPair = crypto.generateKeyPair();

// save a private key into key storage
privateKeyStorage.store(keyPair.getPrivateKey(), "Alice", null);

// publish user's card on the Cards Service
try {
    Card card = cardManager.publishCard(keyPair.getPrivateKey(), keyPair.getPublicKey(), "Alice");
    // Card is created
} catch (Exception e) {
    // Error occured
}
```

### Sign then encrypt data

Virgil Core SDK allows you to use a user's private key and their Virgil Cards to sign and encrypt any kind of data.

In the following example, we load a private key from a customized key storage and get recipient's Card from the Virgil Cards Service. Recipient's Card contains a public key which we will use to encrypt the data and verify a signature.

```java
import com.virgilsecurity.crypto.VirgilCrypto;

VirgilCrypto crypto = new VirgilCrypto();

// prepare a message
String messageToEncrypt = "Hello, Bob!";
byte[] dataToEncrypt = ConvertionUtils.toBytes(messageToEncrypt);

// prepare a user's private key
Tuple<PrivateKey, Map<String, String>> alicePrivateKeyEntry =
        privateKeyStorage.load("Alice");
VirgilPrivateKey alicePrivateKey =
        (VirgilPrivateKey) alicePrivateKeyEntry.getLeft();

// using cardManager search for user's cards on Cards Service
try {
    List<Card> cards = cardManager.searchCards("Bob");
    // Cards are obtained
    List<VirgilPublicKey> bobRelevantCardsPublicKeys = new ArrayList<>();
    for (Card card : cards) {
        if (!card.isOutdated()) {
            bobRelevantCardsPublicKeys.add(
                    (VirgilPublicKey) card.getPublicKey());
        }
    }
    // sign a message with a private key then encrypt on a public key
    byte[] encryptedData = crypto.signThenEncrypt(dataToEncrypt,
            alicePrivateKey, bobRelevantCardsPublicKeys);
} catch (CryptoException | VirgilServiceException e) {
    // Error occured
}
```

### Decrypt data and verify signature

Once the user receives the signed and encrypted message, they can decrypt it with their own private key and verify the signature with the sender's Card:

```java
import com.virgilsecurity.crypto.VirgilCrypto;

VirgilCrypto crypto = new VirgilCrypto();

// prepare a user's private key
Tuple<PrivateKey, Map<String, String>> bobPrivateKeyEntry =
        privateKeyStorage.load("Bob");
VirgilPrivateKey bobPrivateKey =
        (VirgilPrivateKey) bobPrivateKeyEntry.getLeft();

try {
    // using cardManager search for user's cards on Cards Service
    List<Card> cards = cardManager.searchCards("Alice");
    // Cards are obtained
    List<VirgilPublicKey> aliceRelevantCardsPublicKeys = new ArrayList<>();
    for (Card card : cards) {
        if (!card.isOutdated()) {
            aliceRelevantCardsPublicKeys.add(
                    (VirgilPublicKey) card.getPublicKey());
        }
    }

    // decrypt with a private key and verify using a public key
    byte[] decryptedData = crypto.decryptThenVerify(encryptedData,
            bobPrivateKey, aliceRelevantCardsPublicKeys);
} catch (CryptoException | VirgilServiceException e) {
    // Error occured
}
```

### Get Card by its ID

Use the following lines of code to get a user's card from Virgil Cloud by its ID:

```java
// using cardManager get a user's card from the Cards Service
try {
    Card card = cardManager.getCard("f4bf9f7fcbedaba0392f108c59d8f4a38b3838efb64877380171b54475c2ade8");
    // Card is obtained
} catch (CryptoException | VirgilServiceException e) {
    // Error occured
}
```

### Get Card by user's identity

For a single user, use the following lines of code to get a user's Card by a user's `identity`:

```java
try {
    List<Card> cards = cardManager.searchCards("Bob");
    // Cards are obtained
} catch (CryptoException | VirgilServiceException e) {
    // Error occured
}
```

## Run benchmarks

Build artifacts with a command
```bash
mvn clean install -DskipTests
```

A JAR file with benchmarks and all dependencies will be build. You can find it at `/benchmark/target/benchmark.jar`.
You can copy this JAR file to any other machine with install JRE and run with a command
```bash
java -jar <path_to_jar>
```

## Docs

Virgil Security has a powerful set of APIs, and the [Developer Documentation](https://developer.virgilsecurity.com/) can get you started today.

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support

Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).

