# SafeBrowsing Design #

Authors: Brian Ryner, Noe Lutz

## Overview of the SafeBrowsing Service ##

The SafeBrowsing service provides a way for clients, such as web browsers, to warn users if they visit a site that hosts phishing or malware.

Phishing sites impersonate trusted third parties, such as banks, in order to confuse the user into performing some action.  Typically, this action is providing the site with a username and password, which the phisher can then use to log into the trusted site.

Malware sites distribute, either directly or indirectly, software which harms the user's computer.  This can include "spyware" applications, or viruses that put the computer under control of a botnet.  Malware may be installed without the user's knowledge by exploiting security vulnerabilties in the browser or operating system, or they may trick the user into installing the malicious software.

## Protocol Design ##

At a high level, the service works by checking each URL the client loads against a list of known phishing and malware sites.  The list of known sites is represented as _host-suffix / path-prefix_ expressions, also known as just suffix/prefix expressions.  As the name suggests, these expressions can match arbitrary URLs as long as they have the required host suffix and path prefix.   This approach helps protect against sites where the attacker uses many different URLs in order to try to evade blacklists.

Examples of valid suffix/prefix expressions include "google.com/", "some.host.com/123/", and "otherhost.net/some/url.html?q=123".  Note that host suffixes must match an entire host component, so "host.com/" is not a suffix of "otherhost.com/".  If the expression includes query parameters, as in the third example, those must match the URL as well.

Because it would be both inefficient and privacy-invasive to send every URL that is loaded to a server to do this check, the SafeBrowsing protocol takes the approach of downloading this data to the client.  Every few minutes, the client will perform an _update request_ to get new blacklist data from the server.  This process is described in more detail under **Update Process**.

To reduce the size of the downloaded data, the client does not actually receive the full suffix/prefix expressions when they do an update.  Instead, they normally receive a 4-byte _hash prefix_ of the expression.  This is formed by applying a hash function to the expression to generate a 32-byte hash, then simply truncating the result to the first 4 bytes.

When the client wants to check whether a URL is in the blacklist, it first computes all of the suffix/prefix expressions that could potentially apply to the URL.  For example, if the client is loading "`http://www.host.com/service/login.html`", the expressions "host.com/" and "host.com/service/" would both be applicable.  The client computes the hash prefix for each of the expressions, and checks them against the data it has downloaded.

Because the hash prefixes described above may have collisions, a match against a hash prefix is not sufficient to block the URL.  If there is a match, the client must contact the SafeBrowsing service to get the full 32-byte hash corresponding to the prefix.  If this is a match, then the client should warn the user.  This process is described in more detail under **Looking up a URL**.

## Data Format ##

The data that the client downloads is divided into _chunks_, which contain hash prefixes.  There are two types of chunks:  _add chunks_ contain new hash prefixes for the client to match against, while _sub chunks_ tell the client to disregard particular hash prefixes from an add chunk.  Sub chunks allow erroneous entries, known as false positives, to be efficiently removed from the list.

The chunked approach offers two major advantages.  First, it allows clients to download the blacklist data incrementally.  Since the full blacklist may be several megabytes in size, this is a tremendous advantage for clients on slower connections.  Second, this gives the server flexibility in deciding which chunks are most important to send to the client.  For example, since phishing attacks are generally short-lived, it is useful to send the newest data to the client first, before backfilling older data.

Each chunk belongs to a particular _list_.  For example, the list "goog-malware-shavar" contains the hash prefixes for malware sites.  Within each list, the add chunks and sub chunks are independently numbered, starting from 1.  A chunk is uniquely identified by the combination of list name, type, and chunk number, for example "goog-malware-shavar, add chunk 7".

The chunk format is described more fully in [Protocolv2Spec#3.6.\_List\_Contents](Protocolv2Spec#3.6._List_Contents.md).

## Update Process ##

When the client wants to update its local SafeBrowsing data, it contacts the SafeBrowsing server via HTTP and sends a list of all the chunks that it currently has.  An example request might contain the following chunks:

```
goog-malware-shavar:a:20-48,50
goog-malware-shavar:s:10-12
```

This would indicate that the client has all of the goog-malware-shavar add chunks between 20 and 48, inclusive, and chunk 50 (it does not have chunk 49).  It also has sub chunks 10 through 12 for that list.  If the client would like data for a list, but does not have any chunks for it yet, then just the list name is included in the request:

```
googpub-phish-shavar:
```

The response to the update request does not actually contain new chunk data for the client.  Instead, it contains a series of _redirect URLs_ for the client to download, which contain new add and sub chunks.  This design ensures that the chunk data may be cached by proxy servers, which is not true for the update response.  The client fetches each redirect URL given by the update response, and stores the results in its local database.  In addition, the update response may instruct the client to delete chunks that it has already downloaded, if those chunks are no longer relevant.

The update response and the redirect URL data are also signed by the server, using a key that the client has previously obtained.  This allows the client to authenticate the source of the data, and detect whether it has been tampered with, as described in [Protocolv2Spec#4.\_MAC](Protocolv2Spec#4._MAC.md).

**Figure 1** summarizes the update request process.  For a full description of this process, see [Protocolv2Spec#3.4.\_HTTP\_Request\_for\_Data](Protocolv2Spec#3.4._HTTP_Request_for_Data.md) and [Protocolv2Spec#3.5.\_HTTP\_Response\_for\_Data](Protocolv2Spec#3.5._HTTP_Response_for_Data.md).

<p align='center'><img src='http://google-safe-browsing.googlecode.com/svn/wiki/update_process_diagram.png' /></p>
<p align='center'>Figure 1 Overview of the Update Process</p>

## Looking up a URL ##

Before loading a URL or displaying it to the user, the client will look it up in the local SafeBrowsing database.  As described under "Protocol Design", the first step in this process is to compute all of the suffix/prefix expressions that may apply to a URL.  To do this, the client will successively remove host components from the URL until it reaches a TLD, and successively remove path components until it reaches the root (/).  If the URL contains any query parameters, those are also stripped off as path components are removed.

To illustrate this, if the client wants to check the URL "`http://www.somehost.com/path/page.html?args`", it will need to check all of the following expressions:

```
www.somehost.com/path/page.html?args
www.somehost.com/path/page.html
www.somehost.com/path/
www.somehost.com/
somehost.com/path/page.html?args
somehost.com/path/page.html
somehost.com/path/
somehost.com/
```

For each of these expressions, the client will compute the hash and check to see whether the 4-byte hash prefix is listed in an add chunk (and that the prefix has not been removed by a sub chunk).    If there is a match, the next step is to contact the SafeBrowsing service to get the full hashes for that prefix.  These requests are very simple: the client simply sends the hash prefix(es) that it is interested in, and the server responds with a list of full 32-byte hashes.  If the full hash matches the expression the client is looking up, then the expression is definitely present in the blacklist, and the client will warn the user about the URL.

Along with each full hash, the server includes the list name and chunk number that the hash corresponds to.  The client can use this data to cache the full hashes for later use.  This caching is particularly helpful in the case where a hash prefix matches a non-malicious site -- the client can easily see that the site does not match the full hash, and avoid sending the hash request for future visits to the URL.

Like update responses, full hash responses are signed by the server using a previously-obtained key.

For the vast majority of URLs, there will be no hash prefix matches in the client's blacklist, so there will be no need to send a full hash request to the server.  As a result, the privacy impact of these requests is minimal.

**Figure 2** summarizes the lookup process.  A full description of the full-length hash request is in [Protocolv2Spec#3.7.\_HTTP\_Request\_for\_Full-Length\_Hashes](Protocolv2Spec#3.7._HTTP_Request_for_Full-Length_Hashes.md) and [Protocolv2Spec#3.8.\_HTTP\_Response\_for\_Full-Length\_Hashes](Protocolv2Spec#3.8._HTTP_Response_for_Full-Length_Hashes.md), and a description of the lookup semantics is in [Protocolv2Spec#6.\_Performing\_Lookups](Protocolv2Spec#6._Performing_Lookups.md).

<p align='center'><img src='http://google-safe-browsing.googlecode.com/svn/wiki/lookup_diagram.png' /></p>
<p align='center'>Figure 2 Overview of Looking up a URL in the Blacklist</p>

## Further Reading ##

A complete specification the SafeBrowsing protocol is at Protocolv2Spec.