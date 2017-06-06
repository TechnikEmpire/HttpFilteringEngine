# Http Filtering Engine
Transparent filtering TLS proxy that exposes a simple API for filtering of HTTP/S transactions. The engine handles the interception and processing of HTTP/S transactions transparently, and exposes those transactions to the user for optional inspection, with the option to supply your own generated content as HTTP responses. Simply put, this library is the foundation for a modern web content filter.

## Features
 - Transparent TLS capable proxy. This works via automatic packet capture and diversion via the [WinDivert](https://github.com/basil00/Divert) driver and library.
 
 - Management of trusted root certificates.
 
 - Automatic establishment of trust with the host OS. The engine will generate and install a one-session-use root CA, holding the randomly generated, elliptic curve based keypair in memory until the application exits, at which time the key is forever lost and the root CA is rendered useless. This avoids common pitfalls with other similar technology, where improper management or use of trusted self-signed CA's becomes a security risk.
 
 - Automatic rejection of TLS certificates where the issuer could not be verified as a genuine trusted CA. This functions best when you supply the Mozilla [CA-Bundle](https://curl.haxx.se/docs/caextract.html) on startup (see point about management of trusted root CA's). The the user is not even given the option to accept a potentially malicious certificate, the connection is simply refused.
 
 - Non-HTTP passthrough. This is used when the system intercepts a packet flow, inspects it, and determines that it is not a HTTP/S packet flow. The packets will be passed through the engine without inspection or modification so that the source application does not fail.
 
 - Does not trust the host OS trusted CA certificate store. While a user can manually load the host OS's trusted CA's into the engine as trusted CA's, this is not automatic. There are benefits and drawbacks to this, but the real benefit is avoiding the risk of inheriting malicious CA's from the host.
 
 - Transparent upgrade of SSL/TLS sessions between the host and the upstream server. The engine will accept local connections from older, even obsolete secure protocols (SSL3), and then automatically upgrade the upstream connection to current, more secure TLS versions. This can be handy if/when running on older systems with out-dated browsers and such, enabling proper functionality while preventing these obsolete/weaker protocols from being exposed to the public facing network. I stop short however of claiming that this will actually prevent attacks on these weaker protocols. This has not been tested and thus is not proven, I speak purely out of a passive theoretical supposition on that point.
 
 - Ability to hold back the entire payload of a request or a response before sending to the opposite end of the proxy, for the purpose of inspecting the content. Note that this is done in memory presently, and so is not intended for the inspection of very large payloads. The purpose here is to classify simple content, such as text or image content.
 
 - Ability to replace the response payload of a transaction at any given time with any data crafted by the user. This is typically used for injecting an HTML page explaining that content was blocked, or to inject a `204 No Content` HTTP response to gracefully block content (the browser won't complain or show errors).
 
 - When inspecting content, chunked content is automatically decomposed into a plain non-chunked data stream. When this happens, the HTTP headers are automatically adjusted to reflect this state change.
 
 - When inspecting content, all data is automatically decompressed. When this happens, the HTTP headers are automatically adjusted to reflect this state change.
 
 - Works system-wide. There is no process that can escape the packet capture driver. That means that this works with any and every browser that is running on the system.
 
 - Ability to actively select which applications should have their traffic pushed through the filter. Every packet flow is checked to have the originating binary identified by full system path, so you can choose what programs have their traffic filtered. You can operate in a binary mode where you either whitelist one or more applications from being filtered and filter all others, or blacklist one or more applications so only their traffic is filtered and all others pass. Or, you can simply pass all traffic from every application through. Note that when you do filter an application, you're essentially bypassing your local firewall to a degree (if it trusts the application using this library), so there is some burden of consideration inhereted here.
 
 - Ability to detect and block Tor running on the local machine. This same functionality also blocks all SOCKS4 and SOCKS5 proxies that are running on the local machine. As such, Tor, Tor browser and similar software cannot be used to bypass the filter. This is optional, enabled by preprocessor argument during compilation. Not enabled by default. By default, the engine is capturing all traffic destined for port 80 or port 443. Users must build upon this library to detect user searches or navigation to proxy sites. 
 
 
# Building  

HttpFilteringEngine has a lot of dependencies that are complex to build and stage for the project. Some of these dependencies also require third party tools to be installed, making the initial setup process very difficult.

To remove this burden, [BuildBot](https://github.com/TechnikEmpire/BuildBot) was created. This repository contains scripts will be read and processed by BuildBot, and when executed, they fully automate the process of collecting, compiling and staging the project dependencies. They will also fetch temporary, portable copies of required third-party software such as perl and git if they're not installed on your system.

BuildBot is designed to be cross platform, but currently the build scripts for HttpFilteringEngine only support compiling under Windows with Visual Studio 2015.

### To build HttpFilteringEngine with BuildBot you will need:

 - Visual Studio 2015 with C/C++. You can get the free community edition [here](https://www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx).
 - Dotnet core. 
   - Latest version for [Windows x64 host](https://dotnetcli.blob.core.windows.net/dotnet/preview/Installers/Latest/dotnet-win-x64.latest.exe).
   - Latest version for [Windows x86 host](https://dotnetcli.blob.core.windows.net/dotnet/preview/Installers/Latest/dotnet-win-x86.latest.exe).
   - You can find bleeding edge releases [here](https://github.com/dotnet/cli#installers-and-binaries).
  - Dotnet tooling preview for VS2015.
    - Latest version is [here](https://go.microsoft.com/fwlink/?LinkID=827546).

Once you have those requirements installed, you can get all deps setup with the following commands:

# NOTICE
Do not use PowerShell to run BuildBot. Microsoft has crammed PowerShell as the default shell down our throat since Windows 10 Creators Update. Do not use it. Use CMD. If you use PowerShell, files called 'NUL' will get created in submodules, and they cannot be removed, unless you use an arcane command. If this happens to you, remove these 'NUL' files with:

`Del \\?\C:\path\to\NUL`, or from within the current directory: `Del \\?\%CD%\NUL`.

```bash
# Clone BuildBot
git clone --recursive https://github.com/TechnikEmpire/BuildBot.git

#Clone HttpFilteringEngine
git clone https://github.com/TechnikEmpire/HttpFilteringEngine.git

# Move to BuildBot dir and restore required packages.
cd BuildBot
dotnet restore

# Change to the BuildBot portable executable directory and build HttpFilteringEngine
cd BuildBot
dotnet run -C Release,Debug -A x86,x64 -D ..\..\HttpFilteringEngine
```

If this process fails for any reason, you can run the BuildBot clean command, then repeat the build command: 

```bash
# Clean it out and start over. Notice! This will delete all submodules and dir changes!
dotnet run -X -D ..\..\HttpFilteringEngine

# Run build again.
dotnet run -C Release,Debug -A x86,x64 -D ..\..\HttpFilteringEngine
```
#### Notice  
There is currently an issue with junctions that modular boost creates during the clean process. This may cause the clean process to fail the first time. Re-running the clean command on failure will resolve this issue. Windows for some reason may complain that access is denied on first attempt to delete the junction, but it will succeed the second time.

Once this process succeeds, you can open up the Visual Studio solution and build at-will. 

#### Notice  
This configuration process is only required once. You do not need to run it again once the project has been configured successfully.

# Future / TODO

Inspect traffic at the packet level, looking for HTTP headers to non-port-80 connections, and forcing them through the filter as well. This will require a memory system that can successfully map the return path of such connections (map back to the right port after going through the filter).
