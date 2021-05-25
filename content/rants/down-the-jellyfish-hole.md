Title: Down the Jellyfish Hole
Date: 2021-05-06 12:00
Modified: 2021-05-06 12:00
Category: Rants
Tags: rants, cve, CVE-2021-29490, jellyfin, vulnerability, tryhackme
Slug: down-the-jellyfish-hole
Authors: OmegaVoid
Summary: Sometimes rabbit holes aren't a bad thing. The story of how I went to do a Challenge on TryHackMe and came out with a CVE on the other side.

> Note: This post is not a write up of Year of the Jellyfish, but it does contain spoilers. Continue reading at your own risk.

## Year of the Jellyfish

This story starts on the release of [Year of the Jellyfish](https://tryhackme.com/room/yearofthejellyfish), a room by Muirland Oracle (or Muir) that you can do at [TryHackMe.com](https://tryhackme.com). When this room released it started with a pretty interesting challenge. Anyone who rooted the room before 6PM UTC on the 30th of April 2021 would be entered into a prize draw, the big prize would be an OSCP voucher donated by one of the Community Mentors, Fawaz (also known as Papaashell).

I decided I would go deep into this machine and try hard, not because of the prize (I ended up signing up for OSCP anyways afterwards), but more because Muirland promised a realistic machine, and an OSCP-like (in terms of dificulty and ammount of possible rabbit holes in the machine). Additionally, the atmosphere created in the TryHackMe discord became quite positive and fun, so I ended up spending quite a lot of time with this machine. Plus I enjoy Muirland's rooms quite a bit they tend to push me to try harder.

This machine had a few peculiarities, including having a public IP, which meant that I ended up opting to deploy a VPS for the inital enumeration. The machine was somewhat realistically put together with a few Vhosts and several services running on the machine. It was made to look like something someone would host on their basement, with a small business website, a server monitor and a Media server. The only thing that really seemed strange to me in that regard, was seeing an ssh honeypot on the machine.

Without going into too much detail, here's more or less what it looked like.

```
1. Domanin and Vhosts
	a) robyns-petshop.thm
	b) monitorr.robyns-petshop.thm
	c) beta.robyns-petshop.thm
	d) dev.robyns-petshop.thm
2. Ports
	- 22 - OpenSSH 5.9p1 Debian 5ubuntu1.4
	- 80 - Apache httpd 2.4.29 - Robyn's Petshop (redirects to 443)
	- 443 - Apache httpd 2.4.29 - Robyn's Petshop
	- 8000 - http - Under Development
	- 8096 - http - Kestrel - Jellyfin
	- 22222 - OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 
```
Before I went deep into the services hosted on the ports I decided to have a quick look at the vhosts. Beta and dev seemed to be replicating some of the other ports (and I couldn't find any exploitable differences). Monitorr seemed interesting, it was a service monitor solution, it had a login, and the version on the machine had a known [upload vulnerability that could lead to RCE](https://nvd.nist.gov/vuln/detail/CVE-2020-28871). However, testing it out initially I was unable to exploit it, as it seemed Muir had patched it - it would not allow an upload even if we gave the endpoint what seemed valid upload content.

Turns out, that was the route to finish the box, but Muir had patched only enough so that we would have to exploit both the upload functionality and [CVE-2020-28872](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28872). However, having thought that the upload was patched threw me off the mark, specially when you combined it with what Muir said when asked about room creation inspiration on a live event later that evening:

> For me it would usually be coming up with something technical that I like or a technique that I'd want to showcase and then thinking "you know what, this fits in quite nicely with the theme" ... and again, here's a hint...

And this led me down a deep dark path of the Jellyfin rabbit hole. Jellyfin is a free software Media System, where people can collect, manage and stream their media. And the name kind of reminded me of Jellyfish. After hearing this I was fully convinced that Jellyfin must have been the way to obtain a foothold, so I was going to go at it hard. And so I entered the rabbit hole.

## Jellyfin
I went to page 8096, and was greeted by a login page. 

![Jellyfin Login Page](/images/jellyfish/jellyfin-login.png)

Except I didn't have a user or a password. Trying to recover the password, I get a message that I have to be "at home" to be able to do password recovery. Ok. So that's something, Lucky for me, I was able to leak the IP from the internal THM network via one of the requests that the browser makes when accessing Jellyfin. So connected to that internal IP via the THM OpenVPN, rather than going through the public IP. This gave me the ability to attack a bit faster and be a bit less worried about what my traffic was looking like to my ISP.

Once connected via the THM VPN I tried to recover the password for the user 'robyn' (since it's featured in the URL domain). I get the following message.

![Jellyfin Password Recovery PIN message](/images/jellyfish/pin.png)

And a lightbulb turns on in my head. Maybe I can find a way to to leak that pin, use that to get access to upload a file and somehow get a reverse shell that way.
I searched around a bit and found: [CVE-2021-21402](https://nvd.nist.gov/vuln/detail/CVE-2021-21402) which made me think, that's exactly the kind of thing I need to open the file that has the pin. Except one problem, this affects Jellyfin before version 10.7.1, and we had version 10.7.2. Once again, Muiri likes to patch vulnerabilities. Plus, by all signs on your port scan, this was a Linux host.

The running joke at this time on the discord was to offer only "ENUMERATE" to anyone who asked for a hint. So I decided to take that a bit literally and start using a bit of bug hunting methodology and start enumerating all of the Jellyfin API.

I did some fuzzing, finding a few endpoints, but I was also abit smarter than that and looked up the github for Jellyfin, finding the [launch settings config file](https://github.com/jellyfin/jellyfin/blob/91d6ffd731e163bf281348872c2421598fa4edb2/Jellyfin.Server/Properties/launchSettings.json). This file has some interesting information for us to look at:

```python
"Jellyfin.Server (API Docs)": {
      "commandName": "Project",
      "launchBrowser": true,
      "launchUrl": "api-docs/swagger",
      "applicationUrl": "http://localhost:8096",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      },
      "commandLineArgs": "--nowebclient"
    }
```
This was a big one for me, it immediately reminded me of Ben Sadeghipour (a.k.a. NahamSec) who loves to hunt down Swagger UI because it allows you to interact with APIs right there on the documentation (see [this tweet](https://twitter.com/NahamSec/status/1177672652011343873) about it, or [this one](https://twitter.com/NahamSec/status/1280246454884331520)). This piece of knowledge had stuck with me from watching some of Ben's streams and presentations. He is an aswesome person and you should check him out too if you have a chance. 

So I go to http://robyns-petshop.thm:8096/api-docs/swagger and get very detailed documentation for the Jellyfin API, it is indeed Swagger UI after all.

![Jellyfin Swagger UI](/images/jellyfish/jelly-swagger.png)

It felt like a little victory. I had a lot of visibility over everythign that Jellyfin could do, and could easily interact with it all. At this point I was convinced that there was some endpoint that would give me access to the Pin file.

I went through the API, looking for possible vulnerabilities. At this point I had also come to realize that Jellyfin was a fork from previously open source probject named Emby, when it decided to go proprietary. Emby had a previous vulnerability disclosed - [CVE-2020-26948](https://nvd.nist.gov/vuln/detail/CVE-2020-26948).

> Emby Server before 4.5.0 allows SSRF via the Items/RemoteSearch/Image ImageURL parameter.

And this was interesting, that endpoint existed on Jellyfin's API, I poked that that particular endpoint and kept getting Unathorized responses. But strangely, there was another endpoint that did a very similar thing:

> /Images/Remote?ImageUrl=&lt;URL&gt;

And this was immediately strange to me. Why would someone replicate an endpoint that did the same thing but with a different name. This also seemed to break the naming convention that was happening throughout the rest of the API.

Additionally, looking at the API, it seemd that endpoint didn't have HTTP code 401 - Unauthorized as a possible response to that request. It was either 200 or 404. This was interesting. So to do a first test, I tried to access the /web/touchicon.png (the jellyfin logo) on the ImageURL, but requesting it from localhost:8096 instead.

> http://&lt;IP_ADDRESS&gt;:8096/Images/Remote?imageUrl=http://localhost:8096/web/touchicon.png

And it delivered the file to me. Ok. I was onto something. I had SSRF, I could make calls as if I was inside the machine. Maybe Muiri had planted a vulnerable endpoint for us to exploit. 

Alas, I wasn't able to extract the PIN file through it, but I had found something interesting. After having used the vulnerability to poke at the server, scanning for internal http servers, but after quite some time with it I didn't find anything that could help me solve the box.

I let Muri know. He finally let me know that wasn't intended. What seemed like something crafted to be vulnerable, wasn't. So, I went on to Jellyfin's github, and dug deeper to find the code for that endpoint. It would call the provided URL without almost any checks (other than checking if it was already in cache). I had found an unknown vulnerability on the Software.

More or less at the same time, Hydragyrum on Discord was poking at the same API, and after seeing him talk about SSRF on Jellyfin I knew he had found the same thing I did. We got in touch and decided we would work on responsible vulnerability disclosure together for this once we finished the room.

Eventually both me and Hydra finished the room, after realizing Jellyfin wasn't the way forward, it was only a matter of time until we got a back to Monitorr and found the normal foothold, and from there the root was only a matter of propper Enumeration.

## Proof of Concept and Responsible Disclosure

Hydragyrum is another Community Mentor at THM, and someone who has some experience with dockers, which will become relevant in a bit. I spent a day talking to him about the implications of our finding. While doing this we realized the problem of unauthenticated requests on this endpoint wasn't fully new to the organization:

An [issue on the jellyfin repository](https://github.com/jellyfin/jellyfin/issues/5415) had originally mentioned it:

> All (raw) image endpoints in ImageByNameController, ImageController & RemoteImageController are unauthenticated<br>
    This allows probing on whether a specific image exists on the server by guessing item id's (which can maybe done without too much trouble, as I believe item id's are just some MD5 hash? To be confirmed) and then checking on what content (movies, series etc) exist on a given server, without having an account.

However, this failed to recognize the majority of security implications of endpoint's behavior. It went a lot further than leaking images based on IDs. They were clearly aware they had problems with the endpoint, however we felt it necessary to inform Jellyfin more accurately of the implications of this problem.

The next day Hydra assembled a quick docker compose with Jellyfin and an internal Nginx server as well. With that in place, he also created a quick proof of concept, demonstrating not only that we could reach internal resources - in this case the Nginx server - but also do port scanning of the internal network. We only had GET HTTP(S) access without cookies but it was enough to do a lot of internal network recon, and to leak internal resources.

I wrote an email to Jellyfin explaining everything it could do and packaged our docker-compose, an HTTP request demonstrating access to internal resources, and a short python script that could perform port and IP scanning. It wasn't pretty, but it worked, and demonstrated the problem really well.

Within a week they had replied, and only a couple of days later a fix was deployed. Additionally, knowing their code base better than us, the Jellyfin maintainers were able to find a few other endpoints that also contributed to this problem. They ended up removing the affected endpoints all together. A [security advisory](https://github.com/jellyfin/jellyfin/security/advisories/GHSA-rgjw-4fwc-9v96) as well as [CVE-2021-29490](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29490) (currently awaiting analysis) were published, letting everyone know what the problem was and what version patched it.

All in all, I started trying to root a box. Fell into a deep rabbit hole, but ended up applying some Bug Bounty Hunting skills and came out the other side a better hacker, having found a vulnerability where there shouldn't have been one. I often say that failure tends to teach us more than success, but this time failure had turned into success. It may not have been a fast boot-to-root, but in its own way it had felt a lot sweeter.

In the process I'd like to think I helped make Jellyfin a bit safer for their users.