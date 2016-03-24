Status: CURRENT as of 2009/3/10. **This specification is not yet for general use. Do not use this protocol without explicit written permission from Google.**

Copyright 2007 Google Inc.  All Rights Reserved.

Authors: Garrett Casto, Oliver Fisher, Raphaël Moll, Marria Nazif, and Dan Born

Notes: The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

# 1. Background #

Google provides data for the anti-phishing feature implemented in Firefox 2 and Google Desktop. These clients get their blacklist and whitelist data using an "update protocol".  A new protocol, version 2.2, is designed to address some shortcomings of the previous protocol and is described in this specification.

_Note_: This document assumes the reader is familiar with the anti-phishing service. For an overview of the phishing protection in Firefox, see the [design doc on Mozilla.org](http://wiki.mozilla.org/Phishing_Protection:_Design_Documentation). However readers need not be familiar with the details of the version 1 of the protocol to understand the second version.

Version 1 of the update protocol is inefficient and not scalable. Caveats of the version 1 of the protocol include:

  * It does not support partial list updates unless a client has a recent version of the list already fully downloaded. A new client must download the entire list of phishing entries at once or else it will never get any data. As a result, some clients using slow connections take a very long time to download the full list, the request times out, and they never download anything.
  * It sends phishing data to the client in oldest to newest order, which is inefficient for phishing sites since they have a very short lifetime.
  * Expiring old entries requires listing them in updates, which actually consumes bandwidth.
  * Clients only rarely find a match with a 256-bit blacklisted hash, so sending all the data is somewhat wasteful.


**Note:** This is not a license to use the defined protocol. This is merely a description of the protocol.
# 2. Overview #

Version 2 of the update protocol is designed with the following characteristics:

  * Each list type has one canonical list divided into chunks, rather than incrementing list versions.  Each chunk is assigned a unique identifier and describes entries to be added or removed from the blacklist.
  * Clients can recommend a download size that they want to see, although their request is not guaranteed by the server.
  * Clients inherently perform _partial_ updates each time they connect, and the server will send the most valuable data to client first (for example, perhaps the most recent data).
  * The chunk structure is determined by the list type.  Currently, all of the lists contain hashed expressions.
  * Chunks that contain hash values do not contain the full hash, only a prefix for that hash. A new type of request (a gethash request) can be issued to get the list of full-length hashes that start with the prefix.
  * Within each chunk, all hash prefixes are the same length, but different chunks may contain prefixes of different lengths.


As with the previous protocol, the new protocol supports many different blacklists or whitelists. List names are in the form "provider-type-format", e.g. "goog-phish-shavar".  Each item in a list will represent an expression that will match a malicious url, but the exact format depends on the list type and how the content is used is application-specific.  Note that the rest of the specification will generally talk about lists in terms of blacklists but the protocol itself is agnostic to the content of the list.  (See the **List Contents** section below for details.)

The lists are divided into chunks, the smallest unit of data that will be sent to the client. This allows for supporting partial updates to all users, including new users, and allows for more flexibility in choosing which data to send the client.  The actual chunk size is determined by the server.

There are two kind of chunks:

  * "_add_" chunks contain new entries for the list.
  * "_sub_" chunks contains entries that need to be removed from the client's list.


Chunks are assigned a number, which is a sequence number for chunks of the same type.
For example for a given list, there will be:

  * "_Add_" chunk #1, "_add_" chunk #2,..., "_add_" chunk #N.
  * "_Sub_" chunk #1, "_sub_" chunk #2,..., "_sub_" chunk #M.
  * The total number of "_add_" and "_sub_" chunks will generally be different.
  * There is no chunk number 0. Chunk numbers start with 1.
  * Chunk numbers within the same chunk type grow increasingly, without gaps.


For a blacklist, "_add_" chunks contain the new URLs regular expressions or hashes to add to the blacklist and "sub" chunks contains the false positives that need to be removed from the client's blacklist.

In contrast with the previous protocol, the server no longer lists all the URLs that need to be expired. To save bandwidth, the server indicates which chunks need to be deleted by specifying a previously-seen "_add_" chunk number.

**Note:** This spec now references pver 2.2 instead of 2.1.  The change to the protocol was in the handling of empty chunks.  They were illegal in pver 2.1 and used in pver 2.2 to reduce client request size.  This change only affects section 3.5.2.

# 3. Protocol Specification #

The client-server exchange uses a simple pull model: the client connects regularly to the server and pulls some updates. The data exchange can be summarized as follows:

  * The client sends an HTTP POST request to the server and specifies which lists it wants to download. It indicates which chunks it already has. It specifies the desired download size.
  * The server replies with an HTTP error code and an HTTP response. If there is any data, the response contains the chunks for the various requested lists.


Besides the data exchange, the server provides a way for the client to discover which lists are available.

## 3.1. R-BNF ##

This document uses a R-BNF notation, which is a mix between Extended BNF and PCRE-style regular expressions:

  * Rules are in the form: name = definition. Rule names referenced as-is in the definition. Angle brackets may be used to help facilitate discerning the use of rule names.
  * Literals are surrounded by quotation marks: "literal".
  * Sequences: (rule1 rule2) or simply rule1 rule2.
  * Alternatives groups: (rule1 | rule2).
  * Optional groups: `[`rule`]`.
  * Repetition: rule`*` means 0 or more of this rule or this group.
  * Repetition: rule+ means 1 or more of this rule or this group.


The following basic rules that describe the US-ASCII character set are also used as defined in RFC 2616:

  * OCTET = <any 8-bit sequence of data>
  * CHAR = <any US-ASCII character (octets 0 - 127)>
  * UPALPHA = <any US-ASCII uppercase letter "A".."Z">
  * LOALPHA = <any US-ASCII lowercase letter "a".."z">
  * ALPHA = UPALPHA | LOALPHA
  * DIGIT = <any US-ASCII digit "0".."9">
  * CTL = <any US-ASCII control character (octets 0 - 31) and DEL (127)>
  * CR = <US-ASCII CR, carriage return (13)>
  * LF = <US-ASCII LF, line-feed (10)>
  * SP = <US-ASCII SP, space (32)>
  * TAB = <US-ASCII HT, horizontal-tab (9)>
  * <"> = <US-ASCII double-quote mark (34)>
  * LWS = Linear White Space <one or more of SP or TAB>
  * EOF = End of File / End of Stream

## 3.2. HTTP Request for List ##

This is used by clients to discover the available list types.

### 3.2.1. Request's URL ###

The client performs a request by sending an HTTP POST request to the URI:
```
http://safebrowsing.clients.google.com/safebrowsing/list?client=CLIENTID&appver=CLIENTVER&pver=PVER&wrkey=MACKEY
```

Required CGI parameters:

  * The **client** parameter indicates the type of client, e.g. "myapplication".
  * The **appver** parameter indicates the version of the client, e.g. "1.5.2".
  * The **pver** parameter indicates the protocol version that the client supports. Currently this should be "2.2". The format is "major.minor". If we update the protocol, we will make sure that minor revisions are always compatible; however major revision will be incompatible and the server MAY NOT be able to cope with an older protocol.


Optional CGI parameters:

  * The **wrkey** parameter is used by clients who want a MAC for the response. See the **MAC** section below for more details.


Formal R-BNF description:
```
CLIENTID  = (LOALPHA | "-")+
CLIENTVER = DIGIT ["." DIGIT]
PVER      = DIGIT "." DIGIT
MACKEY    = (ALPHA | DIGIT)+
```

Example:
```
http://safebrowsing.clients.google.com/safebrowsing/list?client=myapplication&appver=1.5.2&pver=2.2
```

Client Behavior:

  * The client MUST specify the **client**, **appver** and **pver** CGI parameters.

### 3.2.2. Request's Body ###

There is no body content for this request -- any body data will be ignored by the server.

## 3.3. HTTP Response for List ##

The server replies using the error code and response body of the HTTP response. No specific HTTP headers is set by the server -- some HTTP headers MAY be present but are not authoritative.

### 3.3.1. Response Code ###

The server generates the following HTTP error codes:

  * 200: OK -- Data is available in the HTTP response body.
  * 400: Bad Request -- The HTTP request was not correctly formed. The client did not provide all required CGI parameters.
  * 401: Not Authorized -- The client id is invalid.
  * 503: Service Unavailable -- The server cannot handle the request. Clients MUST follow the backoff behavior specified in the **Request Frequency** section.
  * 505: HTTP Version Not Supported -- The server CANNOT handle the requested protocol major version.

### 3.3.2. Response Body ###

There is no data in the response body for codes in 3xx, 4xx and 5xx.

The response body may be empty.  When present, the response body contains the name of each list that this client can access.
Formal R-BNF description of the response body:
```
BODY     = ([MAC LF] (LISTNAME LF)*) | (REKEY LF) EOF
LISTNAME = (LOALPHA | DIGIT)+ "-" LOALPHA+ "-" (LOALPHA | DIGIT)+
REKEY     = "e:pleaserekey"
```

Example:
```
goog-phish-shavar
goog-malware-shavar
```

## 3.4. HTTP Request for Data ##

This is used by clients who want to get new data for known list types.

### 3.4.1. Request's URL ###

The client performs a datarequest by sending an HTTP POST request to the URI:
```
http://safebrowsing.clients.google.com/safebrowsing/downloads?client=CLIENTID&appver=CLIENTVER&pver=PVER&wrkey=MACKEY
```

CGI parameters are the same as those used in the HTTP Request for List (section 3.2 above.)

Formal R-BNF description:
```
CLIENTID  = (LOALPHA | "-")+
CLIENTVER = DIGIT ["." DIGIT]
PVER      = DIGIT "." DIGIT
MACKEY    = (ALPHA | DIGIT)+
```

Example:
```
http://safebrowsing.clients.google.com/safebrowsing/downloads?client=myapplication&appver=1.5.2&pver=2.2
```

Client Behavior:

  * The client MUST specify the **client**, **appver** and **pver** cgi parameters.

### 3.4.2. Request's body ###

The request body is used to specify what the client has and wants:

  * The client specifies the maxmum size of the download it wants to retrieve.
  * The client specifies which lists it wants to retrieve.
  * For each lists, the client specifies the chunk numbers it already has.


The format of the body is line oriented. Lines are separated by LF. Lines which cannot be understood are ignored by the server.

Formal R-BNF description of the request body:
```
BODY      = [SIZE LF] (LIST LF)+ EOF
SIZE      = "s;" DIGIT+                            # Optional size, in kilobytes and >= 1
LIST      = LISTNAME ";" (["mac"] | (LISTINFO (":" LISTINFO)* [":mac"]))
LISTINFO  = CHUNKTYPE ":" CHUNKLIST
LISTNAME  = (LOALPHA | DIGIT)+ "-" LOALPHA+ "-" (LOALPHA | DIGIT)+
CHUNKTYPE = "a" | "s"                              # 'Add' or 'Sub' chunks
CHUNKLIST = (RANGE | NUMBER) ["," CHUNKLIST]
NUMBER    = DIGIT+                                 # Chunk number >= 1
RANGE     = NUMBER "-" NUMBER
```

Note that the last line of the body MUST have a trailing line-feed.

The size request is optional. If present, the number indicates the ideal maximum response size, in kilobytes, that the server should reply. The size is used a hint by the server; the actual reply size may vary and could be larger or smaller than the ideal size specified by the client.

We strongly recommend that clients omit the size field unless they have a special need to limit the response size. Clients who are operating on a small bandwidth, such as a modem, may want to use the size field to limit the response size. However doing so may cause the client to permanently lag behind. If unsure, clients should omit the size field and let the server decide of the appropriate response size.

Example 1:
```
goog-phish-shavar;a:1-3,5,8:s:4-5
acme-white-shavar;a:1-7:s:1-2
```
In this example, the client requests data for two lists. It then lists the chunks it already has for each list type.

Example 2:
```
s;200
goog-phish-shavar;a:1-3,5,8:s:4-5
acme-white-shavar;a:1-7:s:1-2
```

In this example, the client requests a response size of 200 kilobytes for the two given lists. It then lists the chunks it already has for each list type.

Note that at first the client has no data so it has no chunk number on its side. Generally speaking if a client does not have any chunks of one type it should not list the corresponding chunk type.
Example (inline comments start after a # and are not part of the protocol:)
```
goog-phish-shavar;a:1-5      # The client has 'add' chunks but no 'sub' chunks

acme-malware-shavar;           # The client has no data for this list.

acme-white-shavar;mac        # No data here either and it wants a mac
```

Examples of good chunk lists:
```
goog-phish-shavar;a:1-5,10,12:s:3-8
goog-phish-shavar;a:1,2,3,4,5,10,12,15,16
goog-phish-shavar;a:1-5,10,12,15-16
goog-phish-shavar;a:16-10,2-5,4
```

Examples of bad chunk lists:
```
goog-phish-shavar              # Missing ; at end of list name
goog-phish-shavar;5-1,16-10    # Missing 'a:' or 's:' for chunk type
goog-phish-shavar;a:5-1:s:     # Missing chunk numbers for 's:'
```

Server Behavior:

  * The server MUST reject a request with an empty body.
  * The server MUST ignore ill-formated lines and MUST reply to the correctly formatted ones.
  * The server SHALL try to accommodate the desired response size. The requested size takes into account only chunk data, not any metadata.
  * However if the desired size is less than at least one chunk, the server MUST send at least one chunk.


Client Behavior:

  * The client MUST request at least one list.
  * The last line of the body MUST have a trailing LF character.

## 3.5. HTTP Response for Data ##

The server replies using the error code and response body of the HTTP response. No specific HTTP headers is set by the server -- some HTTP headers MAY be present but are not authoritative.

### 3.5.1. Response Code ###

The server generates the following HTTP error codes:

  * 200: OK -- Data is available in the HTTP response body.
  * 400: Bad Request -- The HTTP request was not correctly formed. The client did not provide all required CGI parameters or the body did not contain any meaningful entries.
  * 403: Forbidden -- The client id is invalid.
  * 503: Service Unavailable -- The server cannot handle the request. Clients MUST follow the backoff behavior specified in the **Request Frequency** section.
  * 505: HTTP Version Not Supported -- The server CANNOT handle the requested protocol major version.

### 3.5.2. Response Body ###

The response body will not be present for codes in 4xx and 5xx.

When present, the response body contains the following information:

  * The next polling interval to use, i.e. the number of seconds before the client should contact the server again.
  * For each list, it's name followed by all chunk data.


The body contains both the chunk data (binary blobs) and the metadata describing the chunks. The metadata is line oriented.
Formal R-BNF description of the response body:
```
BODY      = [(REKEY | MAC) LF] NEXT LF (RESET | (LIST LF)+) EOF
NEXT      = "n:" DIGIT+                               # Minimum delay before polling again in seconds
REKEY     = "e:pleaserekey"
RESET     = "r:pleasereset"
LIST      = "i:" LISTNAME [MAC] (LF LISTDATA)+
LISTNAME  = (LOALPHA | DIGIT | "-")+                  # e.g. "goog-phish-sha128"
MAC       = "," (LOALPHA | DIGIT)+
LISTDATA  = ((REDIRECT_URL | ADDDEL-HEAD | SUBDEL-HEAD) LF)+
REDIRECT_URL = "u:" URL [MAC]
URL       = Defined in RFC 1738
ADDDEL-HEAD  = "ad:" CHUNKLIST
SUBDEL-HEAD  = "sd:" CHUNKLIST
CHUNKLIST = (RANGE | NUMBER) ["," CHUNKLIST]
NUMBER    = DIGIT+                                    # Chunk number >= 1
RANGE     = NUMBER "-" NUMBER
```

Generally speaking lines are in the form "keyword colon parameters". The keyword is limited to one character in this implementation. We reserve the right to use longer keywords later.

A reset response from the server means to clear out all current data in the database
before requesting again.

The response doesn't actually contain the data associated with the lists, instead it tells you were the find the data via redirect urls.  These urls should be visited in the order that they are given, and if an error is encountered fetching any of the urls then the client must NOT fetch any url after that.  Parallel fetching is NOT allowed.

formal R-BNF description of redirect response:
```
BODY      = (ADD-HEAD | SUB-HEAD)+
ADD-HEAD  = "a:" CHUNKNUM ":" HASHLEN ":" CHUNKLEN LF CHUNKDATA   # Length in bytes in decimal
SUB-HEAD  = "s:" CHUNKNUM ":" HASHLEN ":" CHUNKLEN LF CHUNKDATA   # Length in bytes in decimal
CHUNKNUM  = DIGIT+                                   # Sequence number of the chunk
HASHLEN   = DIGIT+                                   # Decimal length of each hash prefix in bytes
CHUNKLEN  = DIGIT+                                   # Size of the chunk data in bytes >= 0
CHUNKDATA = <CHUNKLEN number of unsigned bytes>
```

The MACs used in this response are described in detail in section 4.

The format for _add_ and _sub_ chunks is exactly the same. The number of bytes is followed by one line-feed character (LF, \n) then a binary blob of the indicated length. The length is expressed in bytes in decimal. The LF that follows CHUNKLEN is a separator and is not counted in the length itself. Chunk data encoding is explained in the next section. Chunk data is both encoded and compressed according to which list type it is (see **List Contents** section below). The length described by CHUNKLEN is the size after encoding and/or compression.

The _adddel_ and _subdel_ chunks are used to expire previous _add_ and _sub_ chunks. Consequently they have no associated chunk data. More than one chunk can be specified, either by listing each number or using a range or a combination of both.  When an _add_ chunk is deleted, the client can delete the data associated with that chunk.  When a _sub_ chunk is deleted, the client simply no longer reports that it received that sub chunk in the past.

If there are no chunks of a given type, the entire LISTDATA will be omitted. That is for example if there are no _sub_ or _subdel_ chunks for a given list, there will be no corresponding "s:" or "sd:" information in the metadata.

Chunk types (_add_, _sub_, _adddel_ and _subdel_) can be presented in any order. They can even be intermixed. The order of the chunks depends on the implementation of the server and the clients MUST NOT rely on any empirical behavior. Moreover, the sequence order in which chunks of the same type are present in the stream is not guaranteed.

Chunks may be empty.  That is, it is prefectly valid for CHUNKLEN to be 0.  In this case the prefix size will still be set, but will have no meaning. Chunks may be given this way to prevent fragmentation of requests and reduce request size.

In the case of an empty add chunk, it's possible that the client has or will receive a sub chunk that contains an expression that points to the empty add.  In this case, the client is allowed to drop the sub expression.

Example:
```
n:1200
i:goog-phish-shavar
u:cache.google.com/first_redirect_example
sd:1,2
i:acme-white-shavar
u:cache.google.com/second_redirect_example
ad:1-2,4-5,7
sd:2-6
```
```
contents of first_redirect_example:
a:4:48:1200
[encoded data]
s:3:96:100
[encoded data]
a:6:32:800
[encoded data]
a:7:32:0
s:4:16:40
[encoded data]
```
```
contents of second_redirect_example:
a:9:32:320
[encoded data]
a:10:64:320
[encoded data]
```

In this example, there are no _adddel_ chunks for the "goog-phish-shavar" list, and there are no _sub_ chunks for the "acme-white-shavar" redirect response.

Server Behavior:

  * The server CAN change the "_next_" value (i.e. "n:" line) for each response.


Client Behavior:

  * The client MUST respect the "_next_" value and not contact the server again until the specified delay has expired. See the **Request Frequency** section below for more information on how often the server can be contacted after replying with an HTTP error code.
  * The client MUST ignore a line starting with a keyword that it doesn't understand.

  * If a redirect request returns an error code, the client MUST perform backoff behavior as indicated in the **Request Frequency** section.
  * A client MUST perform a download request again if a redirect request returns an error.
  * The client SHOULD keep all data delivered prior to a bad request.
  * The client MUST refuse to use the whole response if any of the _add_, _sub_, _adddel_ and _subdel_ metadata headers or the binary data cannot be parsed successfully.
  * Upon successful decoding of all the response and all the binary data, the client MUST update its lists in an atomic fashion.

## 3.6. List Contents ##

The contents of each chunk depends on the list type that the chunk belongs to. Currently, the possible lists are:

  * **goog-phish-shavar**: a list of hashed suffix/prefix expressions representing sites that should be blocked because they are hosting phishing pages.
  * **goog-malware-shavar**: a list of suffix/prefix regular expressions representing sites that should be blocked because they are hosting malware pages.


The "shavar" list type relies on suffix/prefix expressions. Each of the suffix/prefix expressions consists of a host suffix (or full host) and a path prefix (or full path).  Note that the path prefix consists of full path components.  If the expression contains the full path, there may optionally be query parameters appended to the path.

Examples:
```
Regular expression:                  http\:\/\/.*\.a\.b\/mypath\/.*
Suffix/prefix expression:            a.b/mypath/
```
```
Regular expression:                  http\:\/\/.*.c\.d\/full\/path\.html?myparam=a
Suffix/prefix regular expression:    c.d/full/path.html?myparam=a
```

### 3.6.1. shavar list format ###

For the "shavar" list format, hash prefixes are used to reduce bandwidth. A hash prefix is some number of the most
significant bytes of a full-length, 256-bit hash. The chunk data header
indicates the length of the hash prefixes in that chunk.

For add chunks, the encoded chunk data is a list of add host key entries. Each
add host key consists of a 32-bit hash prefix for a host key (see below)
followed by a one (1) byte hash prefix count that follows. The hash prefixes are
of the length specified in the chunk data header. Note that the host key hash
prefix is always 32-bits. A host key may be repeated (e.g., there are more than
255 entries for a given host key). There may be no hash prefixes following a
host key, and in such cases the one byte count will be 0. This has special
meaning and indicates that all urls under a host should be considered a match.

Sub chunks are similar, except that in sub host key entries, each hash prefix is
preceded by the add chunk number that contained the add expression.

```
ADD-DATA = (HOSTKEY COUNT [PREFIX]*)+
HOSTKEY  = <4 unsigned bytes>                            # 32-bit hash prefix
COUNT    = <1 unsigned byte>
PREFIX   = <HASHLEN unsigned bytes>
```

```
SUB-DATA    = (HOSTKEY COUNT [ADDCHUNKNUM] [ADDCHUNKNUM PREFIX]*)+
HOSTKEY     = <4 unsigned bytes>                            # 32-bit hash prefix
COUNT       = <1 unsigned byte>
ADDCHUNKNUM = <4 byte unsigned integer in network byte order>
PREFIX      = <HASHLEN unsigned bytes>
```

That is, for SUB-DATA, in the case of a COUNT value of 0, only an ADDCHUNKNUM
will be present following the COUNT, to indicate the add chunk that contained
the host key. In the case of COUNT >= 1, there will be 1 or more [ADDCHUNKNUM
PREFIX] pairs.

To form a host key, first canonicalize the url then take the three most significant host components if there are three or more components in the blacklist entry, or two host components if a third does not exist.  Append a trailing slash (/) to this string, then use the 32 most significant bits of the string's SHAVAR hash as the host key.
To be clear, to match a URL against a host key, a client must try matching based
upon the two most significant host components, and also the three most significant
host components if three such components exist.

An exception to the above exists when the host is an IP address. Here, we form the
host key by taking the SHAVAR hash of the entire host (IP address), NOT two or three
octets of the IP address.

Examples (blacklist entry -> host key, before hashing):
```
google.com/ -> google.com/
sb.google.com/abc/ -> sb.google.com/
a.b.c.google.com/123/ -> c.google.com/
```

Here are some example of "shavar" hashes, based on the examples from
[FIPS-180-2](http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf):

  * Example B1:
    * Input is `"abc"`
    * SHA 256 digest is `ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad`.
    * The 32-bit hash prefix is `ba7816bf`.
  * Example B2:
    * Input is `"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"`
    * SHA 256 digest is `248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1`.
    * The 48-bit hash prefix is `248d6a61 d206`.


Here's a unit test you can use to validate the key computation (in pseudo-C):
```
  // Example B1 from FIPS-180-2
  string input1 = "abc";
  string output1 = TruncatedSha256Prefix(input1, 32);
  int expected1[] = { 0xba, 0x78, 0x16, 0xbf };
  assert(output1.size() == 4);  // 4 bytes == 32 bits
  for (int i = 0; i < output1.size(); i++) assert(output1[i] == expected1[i]);

  // Example B2 from FIPS-180-2
  string input2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  string output2 = TruncatedSha256Prefix(input2, 48);
  int expected2[] = { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06 };
  assert(output2.size() == 6);
  for (int i = 0; i < output2.size(); i++) assert(output2[i] == expected2[i]);

  // Example B3 from FIPS-180-2
  string input3(1000000, 'a');  // 'a' repeated a million times
  string output3 = TruncatedSha256Prefix(input3, 96);
  int expected3[] = { 0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
                      0x81, 0xa1, 0xc7, 0xe2 };
  assert(output3.size() == 12);
  for (int i = 0; i < output3.size(); i++) assert(output3[i] == expected3[i]);
```


## 3.7. HTTP Request for Full-Length Hashes ##

A client may request the list of full-length hashes for a hash prefix.  This usually occurs when a client is about to download content from a url whose calculated hash starts with a prefix listed in a blacklist.  See the Lookup section below for details.

The client MUST not make this request if it received the full length hashes in a previous request, for each list and chunk that the prefix occurs in.

### 3.7.1. Request's URL ###

The client performs a datarequest by sending an HTTP POST request to the URI:
```
http://safebrowsing.clients.google.com/safebrowsing/gethash?client=CLIENTID&appver=CLIENTVER&pver=PVER&wrkey=MACKEY
```
Most CGI parameters are the same as those used in the **HTTP Request for List** (section 3.2 above.)

Formal R-BNF description:

```
CLIENTID  = (LOALPHA | "-")+
CLIENTVER = DIGIT ["." DIGIT]
PVER      = DIGIT "." DIGIT
MACKEY    = (ALPHA | DIGIT)+
```

Example:
```
http://safebrowsing.clients.google.com/safebrowsing/gethash?client=myapplication&appver=1.5.2&pver=2.2
```

Client Behavior:

  * The client MUST specify the **client**, **appver**, and **pver** cgi parameters.

### 3.7.2. Request's body ###

The request body specifies the list of hash prefixes for which the client should
receive full length hashes.

Formal R-BNF description of the request body:
```
BODY       = HEADER LF PREFIXES EOF
HEADER     = PREFIXSIZE ":" LENGTH
PREFIXSIZE = DIGIT+         # Size of each prefix in bytes
LENGTH     = DIGIT+         # Size of PREFIXES in bytes
```

PREFIXES is a list of PREFIXSIZE values. Note that the server returns the full
hash for any matching prefixes given in the request. There may be 0 or more
matches for each prefix given.

## 3.8. HTTP Response for Full-Length Hashes ##

The server replies using the error code and response body of the HTTP response. No specific HTTP headers is set by the server -- some HTTP headers MAY be present but are not authoritative.

### 3.8.1. Response Code ###

The server generates the following HTTP error codes:

  * 200: OK -- Data is available in the HTTP response body.
  * 204: No Content -- There are no full-length hashes with the requested prefix.
  * 400: Bad Request -- The HTTP request was not correctly formed. The client did not provide all required CGI parameters.
  * 403: Forbidden -- The client id is invalid.
  * 503: Service Unavailable -- The server cannot handle the request. Clients MUST follow the backoff behavior specified in the **Request Frequency** section.
  * 505: HTTP Version Not Supported -- The server CANNOT handle the requested protocol major version.

If there are no hashes starting with the requested prefix the server MUST return HTTP error code 204 and the body of the response MUST contain no data.  This is an expected situation and may occur if a client has not yet downloaded an update to a list that deletes the requested prefix.

### 3.8.2. Response Body ###

The response body will not be present for codes in 4xx and 5xx nor for response code 204.

When present, the response body contains the following information:

  * The number of hash entries starting with the requested prefix in decimal.
  * The matching full-length hashes.

Formal R-BNF description of the response body:

```
BODY        = ([MAC LF] HASHENTRY+) | (REKEY LF) EOF
HASHENTRY   = LISTNAME ":" ADDCHUNK ":" HASHDATALEN LF HASHDATA
ADDCHUNK    = DIGIT+                          # Add chunk number
HASHDATALEN = DIGIT+                          # Length of HASHDATA
HASHDATA    = <HASHDATALEN number of unsigned bytes>  # Full length hashes in binary
MAC         = (LOALPHA | DIGIT)+
```

"MAC LF" is only present if the client requested MACing by sending its wrapped
key. HASHDATA is grouped with LISTNAME and ADDCHUNKNUM to correlate it with the
previously received (prefix, LISTNAME, ADDCHUNKNUM).

Each hash in the response MUST be stored as the full length hash for the prefix in the list and chunk indicated in the response, for the length of time that the hash prefix is a valid entry in the chunk.  The full length hash should always be used when performing lookups instead of the prefix, when it is available.  Thus, the client MUST not make any further full length hash requests for that hash, unless a client is following the timing requirements set forth in Section 5.1 and would be unable to issue a warning due to timing constraints in Section 6.3 (e.g. the client has just been launched within the past 5 minutes and so has not yet done a list update, or the list is more than 45 minutes out of date because the client has been backed off and is following the update frequency requested by the server.)

# 4. MAC #

We support a Message Authentication Code in this protocol, similar to the old protocol.

## 4.1. HTTP Request for Key ##

In order to receive a MAC, the client must request a key from the server over a secure connection.  The newkey request should only be called once per client, unless the server requests that the client changes its key (see below).

### 4.1.1. Request's URL ###

The client performs a request by sending an HTTP GET request to the URI:
```
https://sb-ssl.google.com/safebrowsing/newkey?client=CLIENTID&appver=CLIENTVER&pver=PVER
```

CGI parameters are the same as those used in the HTTP Request for List (section 3.2 above.)

Example:
```
https://sb-ssl.google.com/safebrowsing/newkey?client=myapplication&appver=1.5.2&pver=2.2
```

## 4.2. HTTP Response for Key ##

### 4.2.1. Response Code ###

The server generates the following HTTP error codes:

  * 200: OK -- Data is available in the HTTP response body.
  * 400: Bad Request -- The HTTP request was not correctly formed. The client did not provide all required CGI parameters.
  * 401: Not Authorized -- The client id is invalid.
  * 503: Service Unavailable -- The server cannot handle the request. Clients MUST follow the backoff behavior specified in the **Request Frequency** section.
  * 505: HTTP Version Not Supported -- The server CANNOT handle the requested protocol major version.

### 4.2.2. Response Body ###

There is no data in the response body for codes in 3xx, 4xx and 5xx.

When present, the response body contains a client key and a wrapped key.

Formal R-BNF description of the response body:
```
BODY   = "clientkey:" LENGTH ":" MACKEY LF "wrappedkey:" LENGTH ":" MACKEY EOF
LENGTH = DIGIT+
```

Example:
```
clientkey:24:pOAblTUiZFkLSv3xRiXKKQ==
wrappedkey:24:MTqdJvrixHRGAyfebvaQWYda
```

## 4.3. Requesting the MAC ##

The client must include the wrapped key in the request if it wants a MAC. For example, the request will look like this:
```
http://safebrowsing.clients.google.com/safebrowsing/downloads?client=foo&appver=1.5&pver=2.2&wrkey=123
```

The entire response will be protected by a MAC if the **wrkey** parameter is set.  The client can also request a MAC for any individual list by adding the mac keyword after any desired list:
```
s;200
goog-phish-shavar;a:1-3,5,8:s:4-5
acme-white-shavar;a:1-7:s:1-2:mac
```

In the response, the full body MAC will be listed first, and any list MACs will be listed after the redirect url that they belong to:
```
m:MACOFDATA
n:1200
i:goog-phish-shavar
u:cache.google.com/redirect_one
i:acme-white-shavar
u:cache.google.com,FIRST_MAC
d:1-2
```

Boths MACs are HMAC-SHA1 and are websafe base64 encoded. The first MAC is all data in the response after the MAC and trailing LF.  The second covers all the data in the redirect response.

## 4.4. Key Expiration ##

At any time, when a client includes the **wrkey** CGI parameter in a request, the server may prepend "e:pleaserekey" to any response, on a separate line.  This indicates that the client key is no longer valid and that the client should request a new key using the newkey request specified above.

# 5. Request Frequency #

> Providing the data on the server for updates and lookups requires a fair amount of resources. To help maintain a high quality of service, it may be necessary for the download servers to ask the client to make more or less frequent requests.  This is handled differently depending on the type of request.

## 5.1 HTTP Request for Data ##

When requesting a download of data from the server, there are two mechanisms are available to control request frequency:

  * In its response, the server gives an _update_ _interval_, i.e. the delay in seconds before the next connection attempt should occur.
  * The client watches for timeouts or HTTP errors (specifically HTTP response code 3xx, 4xx or 5xx) from the server and if too many errors occur, it increases in the time between requests.  For example, a request returning an error code may be repeated 2 times in 2 minutes, and then not again for an 30-60 minutes.


Client Behavior:

  * The first update request MUST happen at a random interval between 0 and 5 minutes after the browser starts.
  * The second update request MUST happen at the update interval last specified by the server. If this value is unknown, the request MUST happen between 15 and 45 minutes later.
  * After that, each update MUST happen at the update interval last specified by the server.

Client Behavior on error or timeout:

  * If the client receives an error during update, it MUST try again in one minute.
  * If it receives two errors in a row, it MUST continue to skip updates for a period of time defined by the following formula: ` 30mins * (rand + 1) `, where rand is a random number between 0 and 1.  Thus, depending on the value of rand, the client will skip updates for 30-60 minutes.
  * If it receives another (3rd) error, it MUST skip updates for double the length of time.  Thus, depending on the value of rand, the client will skip updates for 60-120 minutes.
  * If it receives another (4th) error, it MUST skip updates for double the length of time.  Thus, depending on the value of rand, the client will skip updates for 120-240 minutes.
  * If it then receives another (5th) error, it MUST skip updates for double the length of time.  Thus, depending on the value of rand, the client will skip updates for 240-480 minutes.
  * For every error after that, it SHOULD continue to check once every 480 minutes until the server responds with a success message.
  * Once the client receives successful HTTP replies, the error stats are reset.

## 5.2 HTTP Request for Full-Length Hashes ##

When requesting a full-length hash from the server, if the client successfully receives a response, it MUST be stored as the full length hash for the prefix in the list and chunk indicated in the response, for the length of time that the hash prefix is a valid entry in the chunk.  The full length hash should always be used when performing lookups instead of the prefix, when it is available.  Thus, the client MUST not make any further full length hash requests for that hash.

Client behavior on error or timeout:

  * If a client receives 2 errors within 5 minutes, it enters backoff mode.
  * After this point, if the client receives one non-error response, or the last error occurred at least 8 hours ago, it exits backoff mode.
  * While in backoff mode, the client MUST not ping for at least a certain amount of time from the last error.  This time changes exponentially until a max of 2 hours.
  * When the client receives the first error, it MUST not ping for at least 30 minutes from the last error.
  * If it receives another error, the client MUST not ping for at least 1 hour.
  * If it receives another error, the client MUST not ping for at least 2 hours.
  * After that, the client MUST wait at least 2 hours between pings.
  * The client has two options for the granularity of error tracking.  The first option is to treat any error during a request for a full length hash equally, triggering backoff mode as specified above.  The second option is to track errors separately by unique hash prefix.  That is, only gethash requests for that particular hash prefix should be skipped for the length of time specified above, extending with each additional error as specified.

# 6. Performing Lookups #

## 6.1. Canonicalization ##
Before lookup in any list, the url must be canonicalized.

We assume that the client has parsed the URL and made it valid according to RFC 2396.  If it's an international url, use the ascii punycode representation.  The URL must include a path component, e.g. 'http://google.com/' must have a trailing slash.

To start, remove any tab (0x09), CR (0x0d), and LF (0x0a) characters from the URL.  Note that escape sequences for these characters, e.g. '%0a', should not be removed.

If the URL ends in a fragment, the fragment should be removed.  For example, 'http://google.com/#frag' would be shortened to 'http://google.com/'.

Next, repeatedly URL-unescape the URL until it has no more hex-encodings.

To canonicalize the hostname:

Extract the hostname from the URL and then follow these steps:

  * Remove all leading and trailing dots
  * Replace consecutive dots with a single dot.
  * If the hostname can be parsed as an IP address, it should be normalized to 4 dot-separated decimal values.  The client should handle any legal IP address encoding, including octal, hex, and fewer than 4 components.
  * Lowercase the whole string.


To canonicalize the path:

  * The sequences "/../" and "/./" in the path should be resolved, by replacing "/./" with "/", and removing "/../" along with the preceding path component.
  * Runs of consecutive slashes should be replaced with a single slash character.


These path canonicalizations should not be applied to the query parameters.

After performing these steps, percent-escape all characters in the URL which are <= ASCII 32, >= 127, "#", or "%". The escapes should use uppercase hex characters.

Below is a set of tests that will help validate a canonicalization implementation.

```
Canonicalize("http://host/%25%32%35") = "http://host/%25";
Canonicalize("http://host/%25%32%35%25%32%35") = "http://host/%25%25";
Canonicalize("http://host/%2525252525252525") = "http://host/%25";
Canonicalize("http://host/asdf%25%32%35asd") = "http://host/asdf%25asd";
Canonicalize("http://host/%%%25%32%35asd%%") = "http://host/%25%25%25asd%25%25";
Canonicalize("http://www.google.com/") = "http://www.google.com/";
Canonicalize("http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/") = "http://168.188.99.26/.secure/www.ebay.com/";
Canonicalize("http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/") = "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/";  
Canonicalize("http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B") = "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+";
Canonicalize("http://3279880203/blah") = "http://195.127.0.11/blah";
Canonicalize("http://www.google.com/blah/..") = "http://www.google.com/";
Canonicalize("www.google.com/") = "http://www.google.com/";
Canonicalize("www.google.com") = "http://www.google.com/";
Canonicalize("http://www.evil.com/blah#frag") = "http://www.evil.com/blah";
Canonicalize("http://www.GOOgle.com/") = "http://www.google.com/";
Canonicalize("http://www.google.com.../") = "http://www.google.com/";
Canonicalize("http://www.google.com/foo\tbar\rbaz\n2") ="http://www.google.com/foobarbaz2";
Canonicalize("http://www.google.com/q?") = "http://www.google.com/q?";
Canonicalize("http://www.google.com/q?r?") = "http://www.google.com/q?r?";
Canonicalize("http://www.google.com/q?r?s") = "http://www.google.com/q?r?s";
Canonicalize("http://evil.com/foo#bar#baz") = "http://evil.com/foo";
Canonicalize("http://evil.com/foo;") = "http://evil.com/foo;";
Canonicalize("http://evil.com/foo?bar;") = "http://evil.com/foo?bar;";
Canonicalize("http://\x01\x80.com/") = "http://%01%80.com/";
Canonicalize("http://notrailingslash.com") = "http://notrailingslash.com/";
Canonicalize("http://www.gotaport.com:1234/") = "http://www.gotaport.com:1234/";
Canonicalize("  http://www.google.com/  ") = "http://www.google.com/";
Canonicalize("http:// leadingspace.com/") = "http://%20leadingspace.com/";
Canonicalize("http://%20leadingspace.com/") = "http://%20leadingspace.com/";
Canonicalize("%20leadingspace.com/") = "http://%20leadingspace.com/";
Canonicalize("https://www.securesite.com/") = "https://www.securesite.com/";
Canonicalize("http://host.com/ab%23cd") = "http://host.com/ab%23cd";
Canonicalize("http://host.com//twoslashes?more//slashes") = "http://host.com/twoslashes?more//slashes";
```

## 6.2. Simplified Regular Expression Lookup ##

Currently all valid list types rely on suffix/prefix expressions, as described in the List Contents section above. To perform a lookup for a given url, the client will try to form different possible host suffix and path prefix combinations and seeing if they match each list. Depending on the list type, the suffix/prefix combination may be hashed before lookup. For these lookups, only the host and path components of the URL are used. The scheme, username, password, and port are disregarded. If query parameters are present in the url, the client will also include a lookup with the full path and query parameters.

For the hostname, the client will try at most 5 different strings. They are:

  * the exact hostname in the url
  * up to 4 hostnames formed by starting with the last 5 components and successively removing the leading component.  The top-level domain can be skipped.  These additional hostnames should not be checked if the host is an IP address.


For the path, the client will also try at most 6 different strings. They are:

  * the exact path of the url, including query parameters
  * the exact path of the url, without query parameters
  * the 4 paths formed by starting at the root (/) and successively appending path components, including a trailing slash.


The following examples should help illustrate the lookup behavior:

For the url http://a.b.c/1/2.html?param=1, the client will try these possible strings:
```
a.b.c/1/2.html?param=1
a.b.c/1/2.html
a.b.c/
a.b.c/1/
b.c/1/2.html?param=1
b.c/1/2.html
b.c/
b.c/1/
```

For the url http://a.b.c.d.e.f.g/1.html, the client will try these possible strings:
```
a.b.c.d.e.f.g/1.html
a.b.c.d.e.f.g/
(Note: skip b.c.d.e.f.g, since we'll take only the last 5 hostname components, and the full hostname)
c.d.e.f.g/1.html
c.d.e.f.g/
d.e.f.g/1.html
d.e.f.g/
e.f.g/1.html
e.f.g/
f.g/1.html
f.g/
```

For the url http://1.2.3.4/1/, the client will try these possible strings:
```
1.2.3.4/1/
1.2.3.4/
```

## 6.3. Age of Data, Usage ##
Applications retrieving data using the API must be certain never to use data older than 45 minutes. What this means specifically is that a warning can be shown only in the following 3 scenarios:

  * A URL matches a full-length hash obtained in an add chunk returned as a response to an HTTP Request for Data, provided that such hash has not been removed from the list (e.g. via a sub chunk), and further provided that the list has been successfully updated via an HTTP Request for Data (where the entire update was successfully processed) within the past 45 minutes from the time a warning is to be provided, or
  * A URL matches a full length hash obtained in a response to an HTTP Request for Full Length Hashes, provided that the prefix of the matching full length hash has not been removed from the list (e.g. via a sub chunk), and further provided that the list has been successfully updated via an HTTP Request for Data (where the entire update was successfully processed) within the past 45 minutes from the time a warning is to be provided, or
  * A URL matches a full length hash obtained in a response to an HTTP Request for Full Length Hashes made within the past 45 minutes from the time a warning is to be provided, provided that such a hash has not been subsequently removed from the list (e.g. via a sub chunk)

Under no other circumstances may a warning be shown.
# 7. References #
  * [RFC 2119](http://www.ietf.org/rfc/rfc2119.txt) -- Keywords for use in RFCs.
  * [RFC 2616](http://www.ietf.org/rfc/rfc2616.txt) -- Hypertext transfer Protocol HTTP/1.1.
  * [Mozilla/Firefox Phishing Protection](http://wiki.mozilla.org/Phishing_Protection).
  * [FIPS-180-2](http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf) -- SHA 256