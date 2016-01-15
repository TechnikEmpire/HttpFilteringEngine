/*
* Copyright (c) 2016 Jesse Nicholson.
*
* This file is part of Http Filtering Engine.
*
* Http Filtering Engine is free software: you can redistribute it and/or
* modify it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 3 of the License, or (at
* your option) any later version.
*
* In addition, as a special exception, the copyright holders give
* permission to link the code of portions of this program with the OpenSSL
* library.
*
* You must obey the GNU General Public License in all respects for all of
* the code used other than OpenSSL. If you modify file(s) with this
* exception, you may extend this exception to your version of the file(s),
* but you are not obligated to do so. If you do not wish to do so, delete
* this exception statement from your version. If you delete this exception
* statement from all source files in the program, then also delete it
* here.
*
* Http Filtering Engine is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
* Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with Http Filtering Engine. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

/*
* Note: Not all fields marked as "Status: Proposed" may in fact be defined
* technically as "informational." Any place where there is a complete
* list of provisional and permanent headers, the status fields are
* incomplete. As such, I operated under the assumption that they fall
* under the category of "proposed" unless explicitly marked as
* "permanent." Some may be actually defined as "informational", but
* currently I'm not willing to read through hundreds if not thousands of
* pages of RFC's and make sure they are correctly marked "proposed" or
* "informational". Standard headers should be marked correctly, that's
* currently the depth of concern with accuracy for these listings.
*
* These listings are not meant to provide 100% accurate summaries of the
* status of the headers, but rather to be a complete list of known headers
* for convenience to the developer, with information about the origin of the
* RFC definition so that one might know where to do to get 100% accurate
* summaries and definitions.
*/

#include <string>

namespace te
{
	namespace httpengine
	{
		namespace util
		{
			namespace http
			{
				namespace headers
				{

					/// <summary>
					/// Header Name: A-IM
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>					
					const std::string AIM = std::string(u8"A-IM");

					/// <summary>
					/// Header Name: Accept
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.2]
					/// </summary>
					const std::string Accept = std::string(u8"Accept");

					/// <summary>
					/// Header Name: Accept-Additions
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string AcceptAdditions = std::string(u8"Accept-Additions");

					/// <summary>
					/// Header Name: Accept-Charset
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.3]
					/// </summary>
					const std::string AcceptCharset = std::string(u8"Accept-Charset");

					/// <summary>
					/// Header Name: Accept-Datetime
					/// Protocol: HTTP
					/// Status: Informational
					/// Defined In: [RFC7089]
					/// </summary>
					const std::string AcceptDatetime = std::string(u8"Accept-Datetime");

					/// <summary>
					/// Header Name: Accept-Encoding
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.4][RFC-ietf-httpbis-cice-03, Section 3]
					/// </summary>
					const std::string AcceptEncoding = std::string(u8"Accept-Encoding");

					/// <summary>
					/// Header Name: Accept-Features
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string AcceptFeatures = std::string(u8"Accept-Features");

					/// <summary>
					/// Header Name: Accept-Language
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.5]
					/// </summary>
					const std::string AcceptLanguage = std::string(u8"Accept-Language");

					/// <summary>
					/// Header Name: Accept-Patch
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC5789]
					/// </summary>
					const std::string AcceptPatch = std::string(u8"Accept-Patch");

					/// <summary>
					/// Header Name: Accept-Ranges
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 2.3]
					/// </summary>
					const std::string AcceptRanges = std::string(u8"Accept-Ranges");

					/// <summary>
					/// Header Name: Access-Control
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControl = std::string(u8"Access-Control");

					/// <summary>
					/// Header Name: Access-Control-Allow-Credentials
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowCredentials = std::string(u8"Access-Control-Allow-Credentials");

					/// <summary>
					/// Header Name: Access-Control-Allow-Headers
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowHeaders = std::string(u8"Access-Control-Allow-Headers");

					/// <summary>
					/// Header Name: Access-Control-Allow-Methods
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowMethods = std::string(u8"Access-Control-Allow-Methods");

					/// <summary>
					/// Header Name: Access-Control-Allow-Origin
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowOrigin = std::string(u8"Access-Control-Allow-Origin");

					/// <summary>
					/// Header Name: Access-Control-Max-Age
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlMaxAge = std::string(u8"Access-Control-Max-Age");

					/// <summary>
					/// Header Name: Access-Control-Request-Headers
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlRequestHeaders = std::string(u8"Access-Control-Request-Headers");

					/// <summary>
					/// Header Name: Access-Control-Request-Method
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlRequestMethod = std::string(u8"Access-Control-Request-Method");

					/// <summary>
					/// Header Name: Age
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.1]
					/// </summary>
					const std::string Age = std::string(u8"Age");

					/// <summary>
					/// Header Name: Allow
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.4.1]
					/// </summary>
					const std::string Allow = std::string(u8"Allow");

					/// <summary>
					/// Header Name: ALPN
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7639, Section 2]
					/// </summary>
					const std::string ALPN = std::string(u8"ALPN");

					/// <summary>
					/// Header Name: Alternates
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Alternates = std::string(u8"Alternates");

					/// <summary>
					/// Header Name: Apply-To-Redirect-Ref
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4437]
					/// </summary>
					const std::string ApplyToRedirectRef = std::string(u8"Apply-To-Redirect-Ref");

					/// <summary>
					/// Header Name: Authentication-Info
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7615, Section 3]
					/// </summary>
					const std::string AuthenticationInfo = std::string(u8"Authentication-Info");

					/// <summary>
					/// Header Name: Authorization
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.2]
					/// </summary>
					const std::string Authorization = std::string(u8"Authorization");

					/// <summary>
					/// Header Name: Base
					/// Protocol: MIME
					/// Status: obsoleted
					/// Defined In: [RFC1808][RFC2068 Section 14.11]
					/// </summary>
					const std::string Base = std::string(u8"Base");

					/// <summary>
					/// Header Name: Body
					/// Protocol: none
					/// Status: reserved
					/// Defined In: [RFC6068]
					/// </summary>
					const std::string Body = std::string(u8"Body");

					/// <summary>
					/// Header Name: C-Ext
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CExt = std::string(u8"C-Ext");

					/// <summary>
					/// Header Name: C-Man
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CMan = std::string(u8"C-Man");

					/// <summary>
					/// Header Name: C-Opt
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string COpt = std::string(u8"C-Opt");

					/// <summary>
					/// Header Name: C-PEP
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CPEP = std::string(u8"C-PEP");

					/// <summary>
					/// Header Name: C-PEP-Info
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CPEPInfo = std::string(u8"C-PEP-Info");

					/// <summary>
					/// Header Name: Cache-Control
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.2]
					/// </summary>
					const std::string CacheControl = std::string(u8"Cache-Control");

					/// <summary>
					/// Header Name: CalDAV-Timezones
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC-ietf-tzdist-caldav-timezone-ref-05, Section 7.1]
					/// </summary>
					const std::string CalDAVTimezones = std::string(u8"CalDAV-Timezones");

					/// <summary>
					/// Header Name: Close
					/// Protocol: HTTP
					/// Status: reserved
					/// Defined In: [RFC7230, Section 8.1]
					/// </summary>
					const std::string Close = std::string(u8"Close");

					/// <summary>
					/// Header Name: Compliance
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Compliance = std::string(u8"Compliance");

					/// <summary>
					/// Header Name: Connection
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 6.1]
					/// </summary>
					const std::string Connection = std::string(u8"Connection");

					/// <summary>
					/// Header Name: Content-Alternative
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string ContentAlternative = std::string(u8"Content-Alternative");

					/// <summary>
					/// Header Name: Content-Base
					/// Protocol: HTTP
					/// Status: obsoleted
					/// Defined In: [RFC2068][RFC2616]
					/// </summary>
					const std::string ContentBase = std::string(u8"Content-Base");

					/// <summary>
					/// Header Name: Content-Description
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string ContentDescription = std::string(u8"Content-Description");

					/// <summary>
					/// Header Name: Content-Disposition
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6266]
					/// </summary>
					const std::string ContentDisposition = std::string(u8"Content-Disposition");

					/// <summary>
					/// Header Name: Content-Duration
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string ContentDuration = std::string(u8"Content-Duration");

					/// <summary>
					/// Header Name: Content-Encoding
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.2.2]
					/// </summary>
					const std::string ContentEncoding = std::string(u8"Content-Encoding");

					/// <summary>
					/// Header Name: Content-features
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string Contentfeatures = std::string(u8"Content-features");

					/// <summary>
					/// Header Name: Content-ID
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentID = std::string(u8"Content-ID");

					/// <summary>
					/// Header Name: Content-Language
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.3.2]
					/// </summary>
					const std::string ContentLanguage = std::string(u8"Content-Language");

					/// <summary>
					/// Header Name: Content-Length
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 3.3.2]
					/// </summary>
					const std::string ContentLength = std::string(u8"Content-Length");

					/// <summary>
					/// Header Name: Content-Location
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.4.2]
					/// </summary>
					const std::string ContentLocation = std::string(u8"Content-Location");

					/// <summary>
					/// Header Name: Content-MD5
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentMD5 = std::string(u8"Content-MD5");

					/// <summary>
					/// Header Name: Content-Range
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 4.2]
					/// </summary>
					const std::string ContentRange = std::string(u8"Content-Range");

					/// <summary>
					/// Header Name: Content-Script-Type
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentScriptType = std::string(u8"Content-Script-Type");

					/// <summary>
					/// Header Name: Content-Style-Type
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentStyleType = std::string(u8"Content-Style-Type");

					/// <summary>
					/// Header Name: Content-Transfer-Encoding
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentTransferEncoding = std::string(u8"Content-Transfer-Encoding");

					/// <summary>
					/// Header Name: Content-Type
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.1.5]
					/// </summary>
					const std::string ContentType = std::string(u8"Content-Type");

					/// <summary>
					/// Header Name: Content-Version
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentVersion = std::string(u8"Content-Version");

					/// <summary>
					/// Header Name: Cookie
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6265]
					/// </summary>
					const std::string Cookie = std::string(u8"Cookie");

					/// <summary>
					/// Header Name: Cookie2
					/// Protocol: HTTP
					/// Status: obsoleted
					/// Defined In: [RFC2965][RFC6265]
					/// </summary>
					const std::string Cookie2 = std::string(u8"Cookie2");

					/// <summary>
					/// Header Name: Cost
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Cost = std::string(u8"Cost");

					/// <summary>
					/// Header Name: DASL
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC5323]
					/// </summary>
					const std::string DASL = std::string(u8"DASL");

					/// <summary>
					/// Header Name: Date
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.1.2]
					/// </summary>
					const std::string Date = std::string(u8"Date");

					/// <summary>
					/// Header Name: DAV
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string DAV = std::string(u8"DAV");

					/// <summary>
					/// Header Name: Default-Style
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DefaultStyle = std::string(u8"Default-Style");

					/// <summary>
					/// Header Name: Delta-Base
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DeltaBase = std::string(u8"Delta-Base");

					/// <summary>
					/// Header Name: Depth
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Depth = std::string(u8"Depth");

					/// <summary>
					/// Header Name: Derived-From
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DerivedFrom = std::string(u8"Derived-From");

					/// <summary>
					/// Header Name: Destination
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Destination = std::string(u8"Destination");

					/// <summary>
					/// Header Name: Differential-ID
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DifferentialID = std::string(u8"Differential-ID");

					/// <summary>
					/// Header Name: Digest
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Digest = std::string(u8"Digest");

					/// <summary>
					/// Header Name: EDIINT-Features
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC6017]
					/// </summary>
					const std::string EDIINTFeatures = std::string(u8"EDIINT-Features");

					/// <summary>
					/// Header Name: ETag
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 2.3]
					/// </summary>
					const std::string ETag = std::string(u8"ETag");

					/// <summary>
					/// Header Name: Expect
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.1.1]
					/// </summary>
					const std::string Expect = std::string(u8"Expect");

					/// <summary>
					/// Header Name: Expires
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.3]
					/// </summary>
					const std::string Expires = std::string(u8"Expires");

					/// <summary>
					/// Header Name: Ext
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Ext = std::string(u8"Ext");

					/// <summary>
					/// Header Name: Forwarded
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7239]
					/// </summary>
					const std::string Forwarded = std::string(u8"Forwarded");

					/// <summary>
					/// Header Name: From
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.5.1]
					/// </summary>
					const std::string From = std::string(u8"From");

					/// <summary>
					/// Header Name: GetProfile
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string GetProfile = std::string(u8"GetProfile");

					/// <summary>
					/// Header Name: Hobareg
					/// Protocol: HTTP
					/// Status: experimental
					/// Defined In: [RFC7486, Section 6.1.1]
					/// </summary>
					const std::string Hobareg = std::string(u8"Hobareg");

					/// <summary>
					/// Header Name: Host
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 5.4]
					/// </summary>
					const std::string Host = std::string(u8"Host");

					/// <summary>
					/// Header Name: HTTP2-Settings
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7540, Section 3.2.1]
					/// </summary>
					const std::string HTTP2Settings = std::string(u8"HTTP2-Settings");

					/// <summary>
					/// Header Name: If
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string If = std::string(u8"If");

					/// <summary>
					/// Header Name: If-Match
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.1]
					/// </summary>
					const std::string IfMatch = std::string(u8"If-Match");

					/// <summary>
					/// Header Name: If-Modified-Since
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.3]
					/// </summary>
					const std::string IfModifiedSince = std::string(u8"If-Modified-Since");

					/// <summary>
					/// Header Name: If-None-Match
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.2]
					/// </summary>
					const std::string IfNoneMatch = std::string(u8"If-None-Match");

					/// <summary>
					/// Header Name: If-Range
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 3.2]
					/// </summary>
					const std::string IfRange = std::string(u8"If-Range");

					/// <summary>
					/// Header Name: If-Schedule-Tag-Match
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6638]
					/// </summary>
					const std::string IfScheduleTagMatch = std::string(u8"If-Schedule-Tag-Match");

					/// <summary>
					/// Header Name: If-Unmodified-Since
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.4]
					/// </summary>
					const std::string IfUnmodifiedSince = std::string(u8"If-Unmodified-Since");

					/// <summary>
					/// Header Name: IM
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string IM = std::string(u8"IM");

					/// <summary>
					/// Header Name: Keep-Alive
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string KeepAlive = std::string(u8"Keep-Alive");

					/// <summary>
					/// Header Name: Label
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Label = std::string(u8"Label");

					/// <summary>
					/// Header Name: Last-Modified
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 2.2]
					/// </summary>
					const std::string LastModified = std::string(u8"Last-Modified");

					/// <summary>
					/// Header Name: Link
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC5988]
					/// </summary>
					const std::string Link = std::string(u8"Link");

					/// <summary>
					/// Header Name: Location
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.2]
					/// </summary>
					const std::string Location = std::string(u8"Location");

					/// <summary>
					/// Header Name: Lock-Token
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string LockToken = std::string(u8"Lock-Token");

					/// <summary>
					/// Header Name: Man
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Man = std::string(u8"Man");

					/// <summary>
					/// Header Name: Max-Forwards
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.1.2]
					/// </summary>
					const std::string MaxForwards = std::string(u8"Max-Forwards");

					/// <summary>
					/// Header Name: Memento-Datetime
					/// Protocol: HTTP
					/// Status: Informational
					/// Defined In: [RFC7089]
					/// </summary>
					const std::string MementoDatetime = std::string(u8"Memento-Datetime");

					/// <summary>
					/// Header Name: Message-ID
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string MessageID = std::string(u8"Message-ID");

					/// <summary>
					/// Header Name: Meter
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Meter = std::string(u8"Meter");

					/// <summary>
					/// Header Name: Method-Check
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string MethodCheck = std::string(u8"Method-Check");

					/// <summary>
					/// Header Name: Method-Check-Expires
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string MethodCheckExpires = std::string(u8"Method-Check-Expires");

					/// <summary>
					/// Header Name: MIME-Version
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Appendix A.1]
					/// </summary>
					const std::string MIMEVersion = std::string(u8"MIME-Version");

					/// <summary>
					/// Header Name: Negotiate
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Negotiate = std::string(u8"Negotiate");

					/// <summary>
					/// Header Name: Non-Compliance
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string NonCompliance = std::string(u8"Non-Compliance");

					/// <summary>
					/// Header Name: Opt
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Opt = std::string(u8"Opt");

					/// <summary>
					/// Header Name: Optional
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Optional = std::string(u8"Optional");

					/// <summary>
					/// Header Name: Ordering-Type
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string OrderingType = std::string(u8"Ordering-Type");

					/// <summary>
					/// Header Name: Origin
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6454]
					/// </summary>
					const std::string Origin = std::string(u8"Origin");

					/// <summary>
					/// Header Name: Overwrite
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Overwrite = std::string(u8"Overwrite");

					/// <summary>
					/// Header Name: P3P
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string P3P = std::string(u8"P3P");

					/// <summary>
					/// Header Name: PEP
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string PEP = std::string(u8"PEP");

					/// <summary>
					/// Header Name: Pep-Info
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string PepInfo = std::string(u8"Pep-Info");

					/// <summary>
					/// Header Name: PICS-Label
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string PICSLabel = std::string(u8"PICS-Label");

					/// <summary>
					/// Header Name: Position
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Position = std::string(u8"Position");

					/// <summary>
					/// Header Name: Pragma
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.4]
					/// </summary>
					const std::string Pragma = std::string(u8"Pragma");

					/// <summary>
					/// Header Name: Prefer
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7240]
					/// </summary>
					const std::string Prefer = std::string(u8"Prefer");

					/// <summary>
					/// Header Name: Preference-Applied
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7240]
					/// </summary>
					const std::string PreferenceApplied = std::string(u8"Preference-Applied");

					/// <summary>
					/// Header Name: ProfileObject
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProfileObject = std::string(u8"ProfileObject");

					/// <summary>
					/// Header Name: Protocol
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Protocol = std::string(u8"Protocol");

					/// <summary>
					/// Header Name: Protocol-Info
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProtocolInfo = std::string(u8"Protocol-Info");

					/// <summary>
					/// Header Name: Protocol-Query
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProtocolQuery = std::string(u8"Protocol-Query");

					/// <summary>
					/// Header Name: Protocol-Request
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProtocolRequest = std::string(u8"Protocol-Request");

					/// <summary>
					/// Header Name: Proxy-Authenticate
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.3]
					/// </summary>
					const std::string ProxyAuthenticate = std::string(u8"Proxy-Authenticate");

					/// <summary>
					/// Header Name: Proxy-Authentication-Info
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7615, Section 4]
					/// </summary>
					const std::string ProxyAuthenticationInfo = std::string(u8"Proxy-Authentication-Info");

					/// <summary>
					/// Header Name: Proxy-Authorization
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.4]
					/// </summary>
					const std::string ProxyAuthorization = std::string(u8"Proxy-Authorization");

					/// <summary>
					/// Header Name: Proxy-Features
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProxyFeatures = std::string(u8"Proxy-Features");

					/// <summary>
					/// Header Name: Proxy-Instruction
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProxyInstruction = std::string(u8"Proxy-Instruction");

					/// <summary>
					/// Header Name: Public
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Public = std::string(u8"Public");

					/// <summary>
					/// Header Name: Public-Key-Pins
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7469]
					/// </summary>
					const std::string PublicKeyPins = std::string(u8"Public-Key-Pins");

					/// <summary>
					/// Header Name: Public-Key-Pins-Report-Only
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7469]
					/// </summary>
					const std::string PublicKeyPinsReportOnly = std::string(u8"Public-Key-Pins-Report-Only");

					/// <summary>
					/// Header Name: Range
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 3.1]
					/// </summary>
					const std::string Range = std::string(u8"Range");

					/// <summary>
					/// Header Name: Redirect-Ref
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4437]
					/// </summary>
					const std::string RedirectRef = std::string(u8"Redirect-Ref");

					/// <summary>
					/// Header Name: Referer
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.5.2]
					/// </summary>
					const std::string Referer = std::string(u8"Referer");

					/// <summary>
					/// Header Name: Referer-Root
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string RefererRoot = std::string(u8"Referer-Root");

					/// <summary>
					/// Header Name: Resolution-Hint
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ResolutionHint = std::string(u8"Resolution-Hint");

					/// <summary>
					/// Header Name: Resolver-Location
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ResolverLocation = std::string(u8"Resolver-Location");

					/// <summary>
					/// Header Name: Retry-After
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.3]
					/// </summary>
					const std::string RetryAfter = std::string(u8"Retry-After");

					/// <summary>
					/// Header Name: Safe
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Safe = std::string(u8"Safe");

					/// <summary>
					/// Header Name: Schedule-Reply
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6638]
					/// </summary>
					const std::string ScheduleReply = std::string(u8"Schedule-Reply");

					/// <summary>
					/// Header Name: Schedule-Tag
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6638]
					/// </summary>
					const std::string ScheduleTag = std::string(u8"Schedule-Tag");

					/// <summary>
					/// Header Name: Sec-WebSocket-Accept
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketAccept = std::string(u8"Sec-WebSocket-Accept");

					/// <summary>
					/// Header Name: Sec-WebSocket-Extensions
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketExtensions = std::string(u8"Sec-WebSocket-Extensions");

					/// <summary>
					/// Header Name: Sec-WebSocket-Key
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketKey = std::string(u8"Sec-WebSocket-Key");

					/// <summary>
					/// Header Name: Sec-WebSocket-Protocol
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketProtocol = std::string(u8"Sec-WebSocket-Protocol");

					/// <summary>
					/// Header Name: Sec-WebSocket-Version
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketVersion = std::string(u8"Sec-WebSocket-Version");

					/// <summary>
					/// Header Name: Security-Scheme
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SecurityScheme = std::string(u8"Security-Scheme");

					/// <summary>
					/// Header Name: Server
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.4.2]
					/// </summary>
					const std::string Server = std::string(u8"Server");

					/// <summary>
					/// Header Name: Set-Cookie
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6265]
					/// </summary>
					const std::string SetCookie = std::string(u8"Set-Cookie");

					/// <summary>
					/// Header Name: Set-Cookie2
					/// Protocol: HTTP
					/// Status: obsoleted
					/// Defined In: [RFC2965][RFC6265]
					/// </summary>
					const std::string SetCookie2 = std::string(u8"Set-Cookie2");

					/// <summary>
					/// Header Name: SetProfile
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SetProfile = std::string(u8"SetProfile");

					/// <summary>
					/// Header Name: SLUG
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC5023]
					/// </summary>
					const std::string SLUG = std::string(u8"SLUG");

					/// <summary>
					/// Header Name: SoapAction
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SoapAction = std::string(u8"SoapAction");

					/// <summary>
					/// Header Name: Status-URI
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string StatusURI = std::string(u8"Status-URI");

					/// <summary>
					/// Header Name: Strict-Transport-Security
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6797]
					/// </summary>
					const std::string StrictTransportSecurity = std::string(u8"Strict-Transport-Security");

					/// <summary>
					/// Header Name: SubOK
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SubOK = std::string(u8"SubOK");

					/// <summary>
					/// Header Name: Subst
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Subst = std::string(u8"Subst");

					/// <summary>
					/// Header Name: Surrogate-Capability
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SurrogateCapability = std::string(u8"Surrogate-Capability");

					/// <summary>
					/// Header Name: Surrogate-Control
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SurrogateControl = std::string(u8"Surrogate-Control");

					/// <summary>
					/// Header Name: TCN
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string TCN = std::string(u8"TCN");

					/// <summary>
					/// Header Name: TE
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 4.3]
					/// </summary>
					const std::string TE = std::string(u8"TE");

					/// <summary>
					/// Header Name: Timeout
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Timeout = std::string(u8"Timeout");

					/// <summary>
					/// Header Name: Title
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Title = std::string(u8"Title");

					/// <summary>
					/// Header Name: Trailer
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 4.4]
					/// </summary>
					const std::string Trailer = std::string(u8"Trailer");

					/// <summary>
					/// Header Name: Transfer-Encoding
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 3.3.1]
					/// </summary>
					const std::string TransferEncoding = std::string(u8"Transfer-Encoding");

					/// <summary>
					/// Header Name: UA-Color
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAColor = std::string(u8"UA-Color");

					/// <summary>
					/// Header Name: UA-Media
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAMedia = std::string(u8"UA-Media");

					/// <summary>
					/// Header Name: UA-Pixels
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAPixels = std::string(u8"UA-Pixels");

					/// <summary>
					/// Header Name: UA-Resolution
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAResolution = std::string(u8"UA-Resolution");

					/// <summary>
					/// Header Name: UA-Windowpixels
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAWindowpixels = std::string(u8"UA-Windowpixels");

					/// <summary>
					/// Header Name: Upgrade
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 6.7]
					/// </summary>
					const std::string Upgrade = std::string(u8"Upgrade");

					/// <summary>
					/// Header Name: URI
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string URI = std::string(u8"URI");

					/// <summary>
					/// Header Name: User-Agent
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.5.3]
					/// </summary>
					const std::string UserAgent = std::string(u8"User-Agent");

					/// <summary>
					/// Header Name: Variant-Vary
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string VariantVary = std::string(u8"Variant-Vary");

					/// <summary>
					/// Header Name: Vary
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.4]
					/// </summary>
					const std::string Vary = std::string(u8"Vary");

					/// <summary>
					/// Header Name: Version
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Version = std::string(u8"Version");

					/// <summary>
					/// Header Name: Via
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 5.7.1]
					/// </summary>
					const std::string Via = std::string(u8"Via");

					/// <summary>
					/// Header Name: Want-Digest
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string WantDigest = std::string(u8"Want-Digest");

					/// <summary>
					/// Header Name: Warning
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.5]
					/// </summary>
					const std::string Warning = std::string(u8"Warning");

					/// <summary>
					/// Header Name: WWW-Authenticate
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.1]
					/// </summary>
					const std::string WWWAuthenticate = std::string(u8"WWW-Authenticate");

					/// <summary>
					/// Header Name: X-Device-Accept
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAccept = std::string(u8"X-Device-Accept");

					/// <summary>
					/// Header Name: X-Device-Accept-Charset
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAcceptCharset = std::string(u8"X-Device-Accept-Charset");

					/// <summary>
					/// Header Name: X-Device-Accept-Encoding
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAcceptEncoding = std::string(u8"X-Device-Accept-Encoding");

					/// <summary>
					/// Header Name: X-Device-Accept-Language
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAcceptLanguage = std::string(u8"X-Device-Accept-Language");

					/// <summary>
					/// Header Name: X-Device-User-Agent
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceUserAgent = std::string(u8"X-Device-User-Agent");

					/// <summary>
					/// Header Name: X-Frame-Options
					/// Protocol: HTTP
					/// Status: Informational
					/// Defined In: [RFC7034]
					/// </summary>
					const std::string XFrameOptions = std::string(u8"X-Frame-Options");
					// Common but non-standard request headers

					/// <summary>
					/// Header Name: X-Requested-With
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XRequestedWith = std::string(u8"X-Requested-With");

					/// <summary>
					/// Header Name: DNT
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string DNT = std::string(u8"DNT");

					/// <summary>
					/// Header Name: X-Forwarded-For
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XForwardedFor = std::string(u8"X-Forwarded-For");

					/// <summary>
					/// Header Name: X-Forwarded-Host
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XForwardedHost = std::string(u8"X-Forwarded-Host");

					/// <summary>
					/// Header Name: X-Forwarded-Proto
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XForwardedProto = std::string(u8"X-Forwarded-Proto");

					/// <summary>
					/// Header Name: Front-End-Https
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string FrontEndHttps = std::string(u8"Front-End-Https");

					/// <summary>
					/// Header Name: X-Http-Method-Override
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XHttpMethodOverride = std::string(u8"X-Http-Method-Override");

					/// <summary>
					/// Header Name: X-ATT-DeviceId
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XATTDeviceId = std::string(u8"X-ATT-DeviceId");

					/// <summary>
					/// Header Name: X-Wap-Profile
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XWapProfile = std::string(u8"X-Wap-Profile");

					/// <summary>
					/// Header Name: Proxy-Connection
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string ProxyConnection = std::string(u8"Proxy-Connection");

					/// <summary>
					/// Header Name: X-UIDH
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XUIDH = std::string(u8"X-UIDH");

					/// <summary>
					/// Header Name: X-Csrf-Token
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XCsrfToken = std::string(u8"X-Csrf-Token");
					// Common but non-standard response headers

					/// <summary>
					/// Header Name: X-XSS-Protection
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XXSSProtection = std::string(u8"X-XSS-Protection");

					/// <summary>
					/// Header Name: Content-Security-Policy
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string ContentSecurityPolicy = std::string(u8"Content-Security-Policy");

					/// <summary>
					/// Header Name: X-Content-Security-Policy
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XContentSecurityPolicy = std::string(u8"X-Content-Security-Policy");

					/// <summary>
					/// Header Name: X-WebKit-CSP
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XWebKitCSP = std::string(u8"X-WebKit-CSP");

					/// <summary>
					/// Header Name: X-Content-Type-Options
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XContentTypeOptions = std::string(u8"X-Content-Type-Options");

					/// <summary>
					/// Header Name: X-Powered-By
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XPoweredBy = std::string(u8"X-Powered-By");

					/// <summary>
					/// Header Name: X-UA-Compatible
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XUACompatible = std::string(u8"X-UA-Compatible");

					/// <summary>
					/// Header Name: X-Content-Duration
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XContentDuration = std::string(u8"X-Content-Duration");

				} /* namespace headers */
			} /* namespace http */
		} /* namespace util */
	} /* namespace httpengine */
} /* namespace te */