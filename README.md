# Http Filtering Engine
Transparent filtering TLS proxy that supports Adblock Plus Filters and CSS Selectors.

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

# What Is It & Future  

HttpFilteringEngine isn't a library in the typical sense, that is, a collection of classes built around supporting specific functionality which are flexible to various purposes. Rather, HttpFilteringEngine is a nearly a full fledged portable application, with the user interface omitted, as this is left to be implemented on a per-platform basis. 

While HttpFilteringEngine does contain a generic TLS capable transparent proxy, this code is presently very tightly bound to the implementation task, that is, the filtering of requests and payloads based on CSS selectors and request filters that use the Adblock Plus filter syntax.

Eventually, the proxy itself will be separated from the filtering Engine and the two things will be published as separate projects.
