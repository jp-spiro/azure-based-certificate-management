# Overview
## Project Background
I am a technologist who likes to keep himself current.  I have several servers in my house dedicated to various things, such as video servers, routers, etc.  I tend to bring the servers up and down and try to limit the services installed.  Because of this, I wanted a wildcard certificate that I could deploy easily without having to install a service for each server.  

## Project Goal
The goal of the project was three-fold:
1. Automatic Let's Encrypt certificate generation and deployment
2. Learn about Azure service offerings
3. Learn about coding with AI

Note: All the code and documentation in this project (except for this readme) is AI generated.  That's why there is no license.  Grok says it releases its code under the MIT license, but I have no way to verify that.  If this code borrows from your code, let me know and I will attribute it or remove it (your choice).

## Project Requirements
I use FedoraCore on the servers and don't like to install extra things.  AI recommended I install `jq` on all the servers.  However, deploying to the FedoraCore would add extra dependencies and this is only for this project, so that's why see `sed` and things like that doing the `JSON` parsing.

The same is true for Python, I like to keep the dependencies low, so that's why you see the JWT done "by hand."

# Pre-AI
## Infrastructure Selection
I use GoDaddy for domain hosting and had originally looked at using GoDaddy for certificates, but their wildcard certificates were quite expensive and seemed to be somewhat cumbersome to deploy.  I then looked at Let's Encrypt and their certificates were easy to use, however, they did not offer an integration with GoDaddy's DNS servers to complete the ACME challenge for the wildcard certificate.  I then looked at the DNS providers that were free or low cost.  I didn't recognize many of the providers, and they seemed to want to host your domain as well.  I then saw that Microsoft offered DNS hosting on Azure that was scriptable.  I had a Microsoft account and wanted to learn about the Azure offering in depth to get a better sense of how cloud-scale apps are designed.  

Here is a summary of the infrastructure so far:
- **GoDaddy**: Domain Hosting
- **Let's Encrypt**: Certificate Authority
- **Microsoft**: DNS

## Microsoft and Azure Initial Impression
The process of just logging into Azure is frustrating (pro-tip, go to https://portal.azure.com rather than https://www.azure.com to save yourself a headache), it would often get confused about what account to use and take me in an authentication loop.  Because I wanted to use this to host my domain, I wanted to use "me@my-domain.com" as the account.  This is possible, and generated a "me@mydomain.onmicrosoft.com" account as well.  So, now I have three accounts with various functions within the Microsoft infrastructure.  Next was figuring out how to set up the Subscription properly, creating the resource group and adding the DNS Zone.  With that finally working, I was able to manually add the ACME challenge and have Let's Encrypt issue the wildcard certificate.

At this point, the thought of spinning up the automation and figuring out which of the hundreds of services were needed was daunting.  The manual way was "good enough" to keep going for a few months, but as I was away more, generating the certificate and manually deploying it became untenable.  I needed to automate it.

# AI
## AI Selection
I tried ChatGPT, Copilot, Gemini and Grok.  ChatGPT seemed fine, but I would have to pay for a subscription.  Copilot and Gemini had given not very useful answers on other projects, so they were disqualified.  Grok had been able to figure ASL (used by BIOSes to detect what devices are present), to extended `initramfs` and eventually deploy the code that was used in a production device.  I had tried to do this on my own, but the documentation for ASL is fragmented and it's not clear and the language itself is obtuse.

## Grok
The development was done in early 2025 with Grok 3.  Development with Grok was by no means smooth.  It would regularly lose the thread and "forget" everything, at which point I had to reseed everything.  I found it best to work on file level implementation with me playing the role of QE.  Grok would submit some code, I would load it and give it the output.  This development was frustrating because it seemed somewhat random.  I found it best to insert the human brain sometimes to get a different output, or check for something obviously wrong, at which point Grok could get back on track.  Several times, it generated just bad code (syntax errors, dumb mistakes), that was frustrating because you are presented with a "You’re right!" and then have to wait 5 minutes for it to give an analysis why it was wrong, talk about all the ways you can fix it, and then maybe give a fix.  I tried to get it to be more brief, but it would either be too brief, or forget.  So I just developed while watching TV or doing other work.

## Areas where Grok excels
Grok excels in two areas.  

1. Parsing large sets of mediocre documentation, Without Grok, I wouldn't have had the patience to parse Microsoft's documentation.  It is a mix of too verbose and not verbose enough (often on the same page).  They will discuss some azure function, but then the example to use it is woefully simple and not useful (the lost helicopter joke is valid 30 years later.)  

2. Implementing complicated mathematical formulas in code. There were some issues implementing the JWT libraries (Idon't remember, but compatibility or something), however since its just deterministic math, AI is able to make a straightforward computation to do it correctly.  It could be viewed as redundant, but its obvious what its doing and there is one fewer dependency to break or be compromised.

## Areas that are lacking
Big picture areas are fairly poor.  It may have some ideas of how to do a project, but you should have background knowledge of what you want to do.  I knew I wanted a simple way to generate and distribute certificates; I had a basic knowledge of Azure to know what the offerings are, etc.  This way you are able to ask specific questions, like "what's the cheapest way to deploy a function to Azure."  It gave a comparison of plans, including Flex Consumption for Azure apps.  It wanted to favor more advanced plans with better debugging, but the goal was to keep this as close to free as possible (US$0.65 a month is close.)

Another area that could be improved is when you ask a question expecting the "best" answer, not just the most common.  This was true with saving the Azure secrets  to the PCs.  There are things like the subscription-id that should be stored securly.  The first pass it talked about generating a key and putting the secret is a normal area on the PC, however, this isn't secure.  I brought up, "what about securing them against the TPM", and got the usual "oh yeah, you're right!".  A few iterations of it messing up how you actually do that and it was working.

## Code improvement
I ran the code back through Grok to rate it and see where it could be improved.  Grok rated its code at 7.5/10, noting there were some hardcoded values and no unit testing.  In the future, maybe I will improve that, but for now, it stays at a note.

# Project Implementation
To see the requirements and how to implement this project see [USING.md](USING.md).  It describes the Azure Services setup, how to get it running, and the client-side setup, including using the TPM to secure sensitive information.