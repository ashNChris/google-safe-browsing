# Testing Protocol #

_status_: **Draft**

We have designed a test suite which will allow clients to test their implementation of this protocol.  Clients will make a request to the test server in the same way they would make a normal update request with one addition. All requests (other than those specifically mentioned below) will contain a "test\_step=" CGI parameter. This parameter will start at "1" and increment by one after every verification step (explained in more detail below).  This parameter helps verify that the client is making requests in the correct order.

In addition to the usual download and redirect requests, clients using the test framework will also make special testing requests to verify that they have correctly parsed the data that they have received.  The first request is "/safebrowsing/verify\_urls" and the response is a list of urls along with a listname and a bit specifiying if the url should be in the associated list. The second request is "/safebrowsing/verify\_database" and the response will be a list of all the hashes that the clients database should contain. This request also has a CGI parameter "chunk\_type" that must be set to either "add" or "sub" to determine the data that the server will respond with.  These requests serve slightly different testing purposes.  The first is to verify that the whole system works properly (canonicalization, hashing, hashserver requests, etc.) but only on a small subset of the data, while the second request will verify that all data is being handled correctly. Clients can choose to only use the first verification if they wish by passing "--ignore\_database\_validation" as a flag to the test server.

After verifying the data the client will make another download request and repeat until no more data can be downloaded. Once the client believes the test is complete, it should make a request to "/test\_complete" to verify that the server agrees. Unlike other requests, the test complete request will not take any CGI parameters. Only if the client and the server agree should the test pass.  If at any point in the test a request returns a 4XX or 5XX response code, the test should fail as well. Pseudo code for such a test is shown below.

```
int step = 1;
GetKey(step);
DownloadLists(step); // This step is optional. Clients may choose to use a hardcoded list instead, but this approach may be fragile.

ServerResponse response;
while (RequestReceivesData(MakeTestRequest(step, &response))) {
  FetchAndApplyRedirects(response, step);
  if (!VerifyCurrentData(step)) {
    FailTest();
  }
  step++;
}

if (!VerifyTestComplete()) {
  FailTest();
}
PassTest();
```

Implementing such a routine will likely require the following changes to client code.
  * Request will have to have a "test\_step" cgi parameter appended to them.  This includes downloads requests, redirect requests, gethash requests, and the new verification requests.
  * Clients will need to change the host of the urls that they are requesting for these tests. The test server should be run on the same machine, and requests should go to "localhost" with the port number set to the port number that the server is running on (configurable via the flag "--port" on the test server)
  * Clients will need to send and parse the response of new requests types, noted below.

**URL Verification**: Request is made to "/safebrowsing/verify\_urls" with the usual CGI parameters. Response will contain urls with associated listnames and an indication if the url should be in the list. Test should pass iff each url is in the correct state.
```
RESPONSE         = [URL_VERIFICATION LF]+
URL_VERIFICATION = URL TAB LISTNAME TAB ("yes" | "no") 
LISTNAME         = (LOALPHA | DIGIT)+ "-" LOALPHA+ "-" (LOALPHA | DIGIT)+
```

**Database Verification**: Request is made to "/safebrowsing/verify\_database" with the usual CGI parameters plus "chunk\_type".  This parameter should be set to either "add" or "sub" and all database entries in the response will be of the specified type. The response will contain hashes that either of prefix length or full length (i.e 256 bits).  The first character of each entry will be either a "y" or an "n" with a "y" indicating the that hash is full length.
```
RESPONSE              = [DATABASE_VERIFICATION]+
DATABASE_VERIFICATION = LISTNAME ":" TYPE ":" CHUNKNUM ":" PREFIXLEN ":" NUMENTRIES (VERIFICATIONENTRIES)*
LISTNAME              = (LOALPHA | DIGIT)+ "-" LOALPHA+ "-" (LOALPHA | DIGIT)+
TYPE                  = "add" | "sub"
VERIFICATIONENTRIES   = ISFULLHASH HASH
ISFULLHASH            = "y" | "n"
```

**Test Complete**: Request is made to "/test\_complete" with no CGI params. Return value is either "yes" or "no", and says if the test believes that all data has been requested and verified.

### Known Issues ###
  * For technical reasons, we currently use the same lists as are used in production (i.e. goog-phish-shavar, goog-malware-shavar, etc.).  It would be better if this test used separate list names to decrease the chance that running the test would affect normal function of the protocol. In the meantime clients need to make sure that the state from the test doesn't interfere with whatever state the client may have had beforehand.
  * Currently we supply database verification for add chunks.  Sub chunks will be added at a later time.