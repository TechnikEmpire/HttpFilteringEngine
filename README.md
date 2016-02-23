# Http Filtering Engine
Transparent filtering TLS proxy that supports Adblock Plus Filters and CSS Selectors.

HttpFilteringEngine isn't a library in the typical sense, that is, a collection of classes built around supporting specific functionality which are flexible to various purposes. Rather, HttpFilteringEngine is a nearly a full fledged portable application, with the user interface omitted, as this is left to be implemented on a per-platform basis. 

While HttpFilteringEngine does contain a generic TLS capable transparent proxy, this code is presently very tightly bound to the implementation task, that is, the filtering of requests and payloads based on CSS selectors and request filters that use the Adblock Plus filter syntax.

Eventually, the proxy itself will be separated from the filtering Engine and the two things will be published as separate projects.
