---
layout: default
title: PE File Structure and Mapping
parent: posts
---

# **Intro**
---
As incident responders, threat analysts, reverse engineers, etc... process injection into native Windows OS binaries is a typical memory evasion seen in a variety of malware and offensive security tools. By injecting malicious DLLs or shellcode into native remote processes, threat actors can attempt to evade on-disk detections and remain in-memory. Popular offensive security tools such as Cobalt Strike typically inject the Beacon DLL into native binaries such as rundll32.exe through the syswow64 (x86) and sysnative (x64) virtual directory by default. 

Observing rundll32 beaconing to the DigitalOcean ASN may not seem as crazy as 2020 has been but it surely isn't going to make it any better for your organization :). So how can you as an analyst further investigate this suspicious in-memory injected process? A quick understanding of the PE file structures and memory mapping process can help you extract and analyze the injected process on disk.

# **PE File Structures**
---
So what is a PE file and what is the importance of it's structure? The Portable Executable (PE) file format is the Common Object File Format (COFF) for executables (EXE) and Dynamic Link Libraries (DLL) for 32-bit and 64-bit binaries on a Windows operating system. The PE file format contains data structures in order for the Windows loader to interperet and correctly map parts of the file into memory. The PE file is broken down into two main sections, the headers and sections. The headers are important data structures for the Windows loader that contain information such as architecture (x86/x64), whether the file is executable, size of each section, preffered virtual base address, etc. We can see an example of a PE file below broken down into the PE headers on the left and different sections on the right:

<img src="{{ site.url }}{{ site.baseurl }}/images/01.png" alt="">
