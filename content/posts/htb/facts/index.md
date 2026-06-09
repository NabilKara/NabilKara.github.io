---
title: "Facts - Hack The Box machine"
date: 2026-06-03
draft: false
tags: ["CMS", "linux", "privelege escalation"]
---


- Difficulty: Easy

- OS: Linux

- Author: LazyTitan333
  
![](solved.png)

An initial nmap scan reveals two open ports : `80` (HTTP) and `23` (SSH)

![](pasted-image-20260602233327.png)

We start by exploring the web page :
![](pasted-image-20260602233347.png)

If we click `Start Exploring` we see a couple of facts , a search bar and a comments section. I browsed the facts and found nothing useful , except that the comments profiles are potential SSH usernames.
We opt for directory enumeration ,for instance, we can use ffuf :

![](pasted-image-20260602233412.png)
  

One output that catches the eye is /admin , visiting it redirects us to /admin/login : 
![](pasted-image-20260602233456.png)

we create an account like this :
![](pasted-image-20260602233521.png)

For a while we may think that we got administrator rights since it shows `Welcome to the Admin Panel`

![](pasted-image-20260602233603.png)

 but if we click the profile , our role is actually `client` ( Sadly ).
  

One thing worth noting is that the page is built using **Camaleon CMS** and that the version is `2.9.0`. Searching for a related CVE we find the **CVE-2024-46987** and here's the [PoC](https://github.com/Goultarde/CVE-2024-46987). This is an **LFI** that affects this version of Camaleon CMS too.

![](pasted-image-20260602233700.png)
  

Reading the /etc/passwd , we see two users at the end `trivia` and `william`.

  ![](pasted-image-20260602233714.png)
  

We can safely guess here and try to read the **user** flag :

![](pasted-image-20260602233812.png)


Since our initial Nmap scan revealed an open SSH port , I thought that we may take advantage of our `LFI` and find a private SSH key for one of these two users and this is what happened lol :

![](pasted-image-20260602233855.png)
  

I already cracked the passphrase , so here is it :

![](pasted-image-20260602233917.png)

Now we can SSH into the user `trivia` and try to escalate our privileges :

![](pasted-image-20260602233935.png)

`sudo -l` reveals an important finding : the user `trivia` can execute `facter` without requiring a password : `(ALL) NOPASSWD: /usr/bin/facter`

  
The immediate intuition is to search in GTFOBins and figure out how to exploit binary :

  ![](pasted-image-20260602234000.png)
  
Oops, this didn't work :

![](pasted-image-20260602234025.png)
  
We noticed in the `sudo -l` that the "Environment Reset option" `env_reset` is set , this blocks custom FACTERLIB, but a quick search reveals that facter supports --external-dir , so this was our way in :

![](pasted-image-20260602234058.png)

Et voilà! we come to the end of this machine . Thanks to the author for the fun machine.

**Note :**

We could've used the **CVE-2026-1776**'s PoC that represents a bypass of the incomplete fix for **CVE-2024-46987**

