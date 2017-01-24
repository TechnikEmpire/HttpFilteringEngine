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
					const std::string AIM{ u8"A-IM" };

					/// <summary>
					/// Header Name: Accept
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.2]
					/// </summary>
					const std::string Accept{ u8"Accept" };

					/// <summary>
					/// Header Name: Accept-Additions
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string AcceptAdditions{ u8"Accept-Additions" };

					/// <summary>
					/// Header Name: Accept-Charset
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.3]
					/// </summary>
					const std::string AcceptCharset{ u8"Accept-Charset" };

					/// <summary>
					/// Header Name: Accept-Datetime
					/// Protocol: HTTP
					/// Status: Informational
					/// Defined In: [RFC7089]
					/// </summary>
					const std::string AcceptDatetime{ u8"Accept-Datetime" };

					/// <summary>
					/// Header Name: Accept-Encoding
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.4][RFC-ietf-httpbis-cice-03, Section 3]
					/// </summary>
					const std::string AcceptEncoding{ u8"Accept-Encoding" };

					/// <summary>
					/// Header Name: Accept-Features
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string AcceptFeatures{ u8"Accept-Features" };

					/// <summary>
					/// Header Name: Accept-Language
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.5]
					/// </summary>
					const std::string AcceptLanguage{ u8"Accept-Language" };

					/// <summary>
					/// Header Name: Accept-Patch
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC5789]
					/// </summary>
					const std::string AcceptPatch{ u8"Accept-Patch" };

					/// <summary>
					/// Header Name: Accept-Ranges
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 2.3]
					/// </summary>
					const std::string AcceptRanges{ u8"Accept-Ranges" };

					/// <summary>
					/// Header Name: Access-Control
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControl{ u8"Access-Control" };

					/// <summary>
					/// Header Name: Access-Control-Allow-Credentials
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowCredentials{ u8"Access-Control-Allow-Credentials" };

					/// <summary>
					/// Header Name: Access-Control-Allow-Headers
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowHeaders{ u8"Access-Control-Allow-Headers" };

					/// <summary>
					/// Header Name: Access-Control-Allow-Methods
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowMethods{ u8"Access-Control-Allow-Methods" };

					/// <summary>
					/// Header Name: Access-Control-Allow-Origin
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowOrigin{ u8"Access-Control-Allow-Origin" };

					/// <summary>
					/// Header Name: Access-Control-Max-Age
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlMaxAge{ u8"Access-Control-Max-Age" };

					/// <summary>
					/// Header Name: Access-Control-Request-Headers
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlRequestHeaders{ u8"Access-Control-Request-Headers" };

					/// <summary>
					/// Header Name: Access-Control-Request-Method
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlRequestMethod{ u8"Access-Control-Request-Method" };

					/// <summary>
					/// Header Name: Age
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.1]
					/// </summary>
					const std::string Age{ u8"Age" };

					/// <summary>
					/// Header Name: Allow
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.4.1]
					/// </summary>
					const std::string Allow{ u8"Allow" };

					/// <summary>
					/// Header Name: ALPN
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7639, Section 2]
					/// </summary>
					const std::string ALPN{ u8"ALPN" };

					/// <summary>
					/// Header Name: Alternates
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Alternates{ u8"Alternates" };

					/// <summary>
					/// Header Name: Apply-To-Redirect-Ref
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4437]
					/// </summary>
					const std::string ApplyToRedirectRef{ u8"Apply-To-Redirect-Ref" };

					/// <summary>
					/// Header Name: Authentication-Info
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7615, Section 3]
					/// </summary>
					const std::string AuthenticationInfo{ u8"Authentication-Info" };

					/// <summary>
					/// Header Name: Authorization
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.2]
					/// </summary>
					const std::string Authorization{ u8"Authorization" };

					/// <summary>
					/// Header Name: Base
					/// Protocol: MIME
					/// Status: obsoleted
					/// Defined In: [RFC1808][RFC2068 Section 14.11]
					/// </summary>
					const std::string Base{ u8"Base" };

					/// <summary>
					/// Header Name: Body
					/// Protocol: none
					/// Status: reserved
					/// Defined In: [RFC6068]
					/// </summary>
					const std::string Body{ u8"Body" };

					/// <summary>
					/// Header Name: C-Ext
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CExt{ u8"C-Ext" };

					/// <summary>
					/// Header Name: C-Man
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CMan{ u8"C-Man" };

					/// <summary>
					/// Header Name: C-Opt
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string COpt{ u8"C-Opt" };

					/// <summary>
					/// Header Name: C-PEP
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CPEP{ u8"C-PEP" };

					/// <summary>
					/// Header Name: C-PEP-Info
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CPEPInfo{ u8"C-PEP-Info" };

					/// <summary>
					/// Header Name: Cache-Control
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.2]
					/// </summary>
					const std::string CacheControl{ u8"Cache-Control" };

					/// <summary>
					/// Header Name: CalDAV-Timezones
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC-ietf-tzdist-caldav-timezone-ref-05, Section 7.1]
					/// </summary>
					const std::string CalDAVTimezones{ u8"CalDAV-Timezones" };

					/// <summary>
					/// Header Name: Close
					/// Protocol: HTTP
					/// Status: reserved
					/// Defined In: [RFC7230, Section 8.1]
					/// </summary>
					const std::string Close{ u8"Close" };

					/// <summary>
					/// Header Name: Compliance
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Compliance{ u8"Compliance" };

					/// <summary>
					/// Header Name: Connection
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 6.1]
					/// </summary>
					const std::string Connection{ u8"Connection" };

					/// <summary>
					/// Header Name: Content-Alternative
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string ContentAlternative{ u8"Content-Alternative" };

					/// <summary>
					/// Header Name: Content-Base
					/// Protocol: HTTP
					/// Status: obsoleted
					/// Defined In: [RFC2068][RFC2616]
					/// </summary>
					const std::string ContentBase{ u8"Content-Base" };

					/// <summary>
					/// Header Name: Content-Description
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string ContentDescription{ u8"Content-Description" };

					/// <summary>
					/// Header Name: Content-Disposition
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6266]
					/// </summary>
					const std::string ContentDisposition{ u8"Content-Disposition" };

					/// <summary>
					/// Header Name: Content-Duration
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string ContentDuration{ u8"Content-Duration" };

					/// <summary>
					/// Header Name: Content-Encoding
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.2.2]
					/// </summary>
					const std::string ContentEncoding{ u8"Content-Encoding" };

					/// <summary>
					/// Header Name: Content-features
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string Contentfeatures{ u8"Content-features" };

					/// <summary>
					/// Header Name: Content-ID
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentID{ u8"Content-ID" };

					/// <summary>
					/// Header Name: Content-Language
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.3.2]
					/// </summary>
					const std::string ContentLanguage{ u8"Content-Language" };

					/// <summary>
					/// Header Name: Content-Length
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 3.3.2]
					/// </summary>
					const std::string ContentLength{ u8"Content-Length" };

					/// <summary>
					/// Header Name: Content-Location
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.4.2]
					/// </summary>
					const std::string ContentLocation{ u8"Content-Location" };

					/// <summary>
					/// Header Name: Content-MD5
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentMD5{ u8"Content-MD5" };

					/// <summary>
					/// Header Name: Content-Range
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 4.2]
					/// </summary>
					const std::string ContentRange{ u8"Content-Range" };

					/// <summary>
					/// Header Name: Content-Script-Type
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentScriptType{ u8"Content-Script-Type" };

					/// <summary>
					/// Header Name: Content-Style-Type
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentStyleType{ u8"Content-Style-Type" };

					/// <summary>
					/// Header Name: Content-Transfer-Encoding
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentTransferEncoding{ u8"Content-Transfer-Encoding" };

					/// <summary>
					/// Header Name: Content-Type
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.1.5]
					/// </summary>
					const std::string ContentType{ u8"Content-Type" };

					/// <summary>
					/// Header Name: Content-Version
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentVersion{ u8"Content-Version" };

					/// <summary>
					/// Header Name: Cookie
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6265]
					/// </summary>
					const std::string Cookie{ u8"Cookie" };

					/// <summary>
					/// Header Name: Cookie2
					/// Protocol: HTTP
					/// Status: obsoleted
					/// Defined In: [RFC2965][RFC6265]
					/// </summary>
					const std::string Cookie2{ u8"Cookie2" };

					/// <summary>
					/// Header Name: Cost
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Cost{ u8"Cost" };

					/// <summary>
					/// Header Name: DASL
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC5323]
					/// </summary>
					const std::string DASL{ u8"DASL" };

					/// <summary>
					/// Header Name: Date
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.1.2]
					/// </summary>
					const std::string Date{ u8"Date" };

					/// <summary>
					/// Header Name: DAV
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string DAV{ u8"DAV" };

					/// <summary>
					/// Header Name: Default-Style
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DefaultStyle{ u8"Default-Style" };

					/// <summary>
					/// Header Name: Delta-Base
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DeltaBase{ u8"Delta-Base" };

					/// <summary>
					/// Header Name: Depth
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Depth{ u8"Depth" };

					/// <summary>
					/// Header Name: Derived-From
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DerivedFrom{ u8"Derived-From" };

					/// <summary>
					/// Header Name: Destination
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Destination{ u8"Destination" };

					/// <summary>
					/// Header Name: Differential-ID
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DifferentialID{ u8"Differential-ID" };

					/// <summary>
					/// Header Name: Digest
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Digest{ u8"Digest" };

					/// <summary>
					/// Header Name: EDIINT-Features
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC6017]
					/// </summary>
					const std::string EDIINTFeatures{ u8"EDIINT-Features" };

					/// <summary>
					/// Header Name: ETag
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 2.3]
					/// </summary>
					const std::string ETag{ u8"ETag" };

					/// <summary>
					/// Header Name: Expect
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.1.1]
					/// </summary>
					const std::string Expect{ u8"Expect" };

					/// <summary>
					/// Header Name: Expires
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.3]
					/// </summary>
					const std::string Expires{ u8"Expires" };

					/// <summary>
					/// Header Name: Ext
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Ext{ u8"Ext" };

					/// <summary>
					/// Header Name: Forwarded
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7239]
					/// </summary>
					const std::string Forwarded{ u8"Forwarded" };

					/// <summary>
					/// Header Name: From
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.5.1]
					/// </summary>
					const std::string From{ u8"From" };

					/// <summary>
					/// Header Name: GetProfile
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string GetProfile{ u8"GetProfile" };

					/// <summary>
					/// Header Name: Hobareg
					/// Protocol: HTTP
					/// Status: experimental
					/// Defined In: [RFC7486, Section 6.1.1]
					/// </summary>
					const std::string Hobareg{ u8"Hobareg" };

					/// <summary>
					/// Header Name: Host
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 5.4]
					/// </summary>
					const std::string Host{ u8"Host" };

					/// <summary>
					/// Header Name: HTTP2-Settings
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7540, Section 3.2.1]
					/// </summary>
					const std::string HTTP2Settings{ u8"HTTP2-Settings" };

					/// <summary>
					/// Header Name: If
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string If{ u8"If" };

					/// <summary>
					/// Header Name: If-Match
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.1]
					/// </summary>
					const std::string IfMatch{ u8"If-Match" };

					/// <summary>
					/// Header Name: If-Modified-Since
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.3]
					/// </summary>
					const std::string IfModifiedSince{ u8"If-Modified-Since" };

					/// <summary>
					/// Header Name: If-None-Match
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.2]
					/// </summary>
					const std::string IfNoneMatch{ u8"If-None-Match" };

					/// <summary>
					/// Header Name: If-Range
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 3.2]
					/// </summary>
					const std::string IfRange{ u8"If-Range" };

					/// <summary>
					/// Header Name: If-Schedule-Tag-Match
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6638]
					/// </summary>
					const std::string IfScheduleTagMatch{ u8"If-Schedule-Tag-Match" };

					/// <summary>
					/// Header Name: If-Unmodified-Since
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.4]
					/// </summary>
					const std::string IfUnmodifiedSince{ u8"If-Unmodified-Since" };

					/// <summary>
					/// Header Name: IM
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string IM{ u8"IM" };

					/// <summary>
					/// Header Name: Keep-Alive
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string KeepAlive{ u8"Keep-Alive" };

					/// <summary>
					/// Header Name: Label
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Label{ u8"Label" };

					/// <summary>
					/// Header Name: Last-Modified
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 2.2]
					/// </summary>
					const std::string LastModified{ u8"Last-Modified" };

					/// <summary>
					/// Header Name: Link
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC5988]
					/// </summary>
					const std::string Link{ u8"Link" };

					/// <summary>
					/// Header Name: Location
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.2]
					/// </summary>
					const std::string Location{ u8"Location" };

					/// <summary>
					/// Header Name: Lock-Token
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string LockToken{ u8"Lock-Token" };

					/// <summary>
					/// Header Name: Man
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Man{ u8"Man" };

					/// <summary>
					/// Header Name: Max-Forwards
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.1.2]
					/// </summary>
					const std::string MaxForwards{ u8"Max-Forwards" };

					/// <summary>
					/// Header Name: Memento-Datetime
					/// Protocol: HTTP
					/// Status: Informational
					/// Defined In: [RFC7089]
					/// </summary>
					const std::string MementoDatetime{ u8"Memento-Datetime" };

					/// <summary>
					/// Header Name: Message-ID
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string MessageID{ u8"Message-ID" };

					/// <summary>
					/// Header Name: Meter
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Meter{ u8"Meter" };

					/// <summary>
					/// Header Name: Method-Check
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string MethodCheck{ u8"Method-Check" };

					/// <summary>
					/// Header Name: Method-Check-Expires
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string MethodCheckExpires{ u8"Method-Check-Expires" };

					/// <summary>
					/// Header Name: MIME-Version
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Appendix A.1]
					/// </summary>
					const std::string MIMEVersion{ u8"MIME-Version" };

					/// <summary>
					/// Header Name: Negotiate
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Negotiate{ u8"Negotiate" };

					/// <summary>
					/// Header Name: Non-Compliance
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string NonCompliance{ u8"Non-Compliance" };

					/// <summary>
					/// Header Name: Opt
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Opt{ u8"Opt" };

					/// <summary>
					/// Header Name: Optional
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Optional{ u8"Optional" };

					/// <summary>
					/// Header Name: Ordering-Type
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string OrderingType{ u8"Ordering-Type" };

					/// <summary>
					/// Header Name: Origin
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6454]
					/// </summary>
					const std::string Origin{ u8"Origin" };

					/// <summary>
					/// Header Name: Overwrite
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Overwrite{ u8"Overwrite" };

					/// <summary>
					/// Header Name: P3P
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string P3P{ u8"P3P" };

					/// <summary>
					/// Header Name: PEP
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string PEP{ u8"PEP" };

					/// <summary>
					/// Header Name: Pep-Info
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string PepInfo{ u8"Pep-Info" };

					/// <summary>
					/// Header Name: PICS-Label
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string PICSLabel{ u8"PICS-Label" };

					/// <summary>
					/// Header Name: Position
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Position{ u8"Position" };

					/// <summary>
					/// Header Name: Pragma
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.4]
					/// </summary>
					const std::string Pragma{ u8"Pragma" };

					/// <summary>
					/// Header Name: Prefer
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7240]
					/// </summary>
					const std::string Prefer{ u8"Prefer" };

					/// <summary>
					/// Header Name: Preference-Applied
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7240]
					/// </summary>
					const std::string PreferenceApplied{ u8"Preference-Applied" };

					/// <summary>
					/// Header Name: ProfileObject
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProfileObject{ u8"ProfileObject" };

					/// <summary>
					/// Header Name: Protocol
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Protocol{ u8"Protocol" };

					/// <summary>
					/// Header Name: Protocol-Info
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProtocolInfo{ u8"Protocol-Info" };

					/// <summary>
					/// Header Name: Protocol-Query
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProtocolQuery{ u8"Protocol-Query" };

					/// <summary>
					/// Header Name: Protocol-Request
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProtocolRequest{ u8"Protocol-Request" };

					/// <summary>
					/// Header Name: Proxy-Authenticate
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.3]
					/// </summary>
					const std::string ProxyAuthenticate{ u8"Proxy-Authenticate" };

					/// <summary>
					/// Header Name: Proxy-Authentication-Info
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7615, Section 4]
					/// </summary>
					const std::string ProxyAuthenticationInfo{ u8"Proxy-Authentication-Info" };

					/// <summary>
					/// Header Name: Proxy-Authorization
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.4]
					/// </summary>
					const std::string ProxyAuthorization{ u8"Proxy-Authorization" };

					/// <summary>
					/// Header Name: Proxy-Features
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProxyFeatures{ u8"Proxy-Features" };

					/// <summary>
					/// Header Name: Proxy-Instruction
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProxyInstruction{ u8"Proxy-Instruction" };

					/// <summary>
					/// Header Name: Public
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Public{ u8"Public" };

					/// <summary>
					/// Header Name: Public-Key-Pins
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7469]
					/// </summary>
					const std::string PublicKeyPins{ u8"Public-Key-Pins" };

					/// <summary>
					/// Header Name: Public-Key-Pins-Report-Only
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7469]
					/// </summary>
					const std::string PublicKeyPinsReportOnly{ u8"Public-Key-Pins-Report-Only" };

					/// <summary>
					/// Header Name: Range
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 3.1]
					/// </summary>
					const std::string Range{ u8"Range" };

					/// <summary>
					/// Header Name: Redirect-Ref
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4437]
					/// </summary>
					const std::string RedirectRef{ u8"Redirect-Ref" };

					/// <summary>
					/// Header Name: Referer
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.5.2]
					/// </summary>
					const std::string Referer{ u8"Referer" };

					/// <summary>
					/// Header Name: Referer-Root
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string RefererRoot{ u8"Referer-Root" };

					/// <summary>
					/// Header Name: Resolution-Hint
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ResolutionHint{ u8"Resolution-Hint" };

					/// <summary>
					/// Header Name: Resolver-Location
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ResolverLocation{ u8"Resolver-Location" };

					/// <summary>
					/// Header Name: Retry-After
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.3]
					/// </summary>
					const std::string RetryAfter{ u8"Retry-After" };

					/// <summary>
					/// Header Name: Safe
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Safe{ u8"Safe" };

					/// <summary>
					/// Header Name: Schedule-Reply
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6638]
					/// </summary>
					const std::string ScheduleReply{ u8"Schedule-Reply" };

					/// <summary>
					/// Header Name: Schedule-Tag
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6638]
					/// </summary>
					const std::string ScheduleTag{ u8"Schedule-Tag" };

					/// <summary>
					/// Header Name: Sec-WebSocket-Accept
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketAccept{ u8"Sec-WebSocket-Accept" };

					/// <summary>
					/// Header Name: Sec-WebSocket-Extensions
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketExtensions{ u8"Sec-WebSocket-Extensions" };

					/// <summary>
					/// Header Name: Sec-WebSocket-Key
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketKey{ u8"Sec-WebSocket-Key" };

					/// <summary>
					/// Header Name: Sec-WebSocket-Protocol
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketProtocol{ u8"Sec-WebSocket-Protocol" };

					/// <summary>
					/// Header Name: Sec-WebSocket-Version
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketVersion{ u8"Sec-WebSocket-Version" };

					/// <summary>
					/// Header Name: Security-Scheme
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SecurityScheme{ u8"Security-Scheme" };

					/// <summary>
					/// Header Name: Server
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.4.2]
					/// </summary>
					const std::string Server{ u8"Server" };

					/// <summary>
					/// Header Name: Set-Cookie
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6265]
					/// </summary>
					const std::string SetCookie{ u8"Set-Cookie" };

					/// <summary>
					/// Header Name: Set-Cookie2
					/// Protocol: HTTP
					/// Status: obsoleted
					/// Defined In: [RFC2965][RFC6265]
					/// </summary>
					const std::string SetCookie2{ u8"Set-Cookie2" };

					/// <summary>
					/// Header Name: SetProfile
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SetProfile{ u8"SetProfile" };

					/// <summary>
					/// Header Name: SLUG
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC5023]
					/// </summary>
					const std::string SLUG{ u8"SLUG" };

					/// <summary>
					/// Header Name: SoapAction
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SoapAction{ u8"SoapAction" };

					/// <summary>
					/// Header Name: Status-URI
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string StatusURI{ u8"Status-URI" };

					/// <summary>
					/// Header Name: Strict-Transport-Security
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6797]
					/// </summary>
					const std::string StrictTransportSecurity{ u8"Strict-Transport-Security" };

					/// <summary>
					/// Header Name: SubOK
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SubOK{ u8"SubOK" };

					/// <summary>
					/// Header Name: Subst
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Subst{ u8"Subst" };

					/// <summary>
					/// Header Name: Surrogate-Capability
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SurrogateCapability{ u8"Surrogate-Capability" };

					/// <summary>
					/// Header Name: Surrogate-Control
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SurrogateControl{ u8"Surrogate-Control" };

					/// <summary>
					/// Header Name: TCN
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string TCN{ u8"TCN" };

					/// <summary>
					/// Header Name: TE
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 4.3]
					/// </summary>
					const std::string TE{ u8"TE" };

					/// <summary>
					/// Header Name: Timeout
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Timeout{ u8"Timeout" };

					/// <summary>
					/// Header Name: Title
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Title{ u8"Title" };

					/// <summary>
					/// Header Name: Trailer
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 4.4]
					/// </summary>
					const std::string Trailer{ u8"Trailer" };

					/// <summary>
					/// Header Name: Transfer-Encoding
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 3.3.1]
					/// </summary>
					const std::string TransferEncoding{ u8"Transfer-Encoding" };

					/// <summary>
					/// Header Name: UA-Color
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAColor{ u8"UA-Color" };

					/// <summary>
					/// Header Name: UA-Media
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAMedia{ u8"UA-Media" };

					/// <summary>
					/// Header Name: UA-Pixels
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAPixels{ u8"UA-Pixels" };

					/// <summary>
					/// Header Name: UA-Resolution
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAResolution{ u8"UA-Resolution" };

					/// <summary>
					/// Header Name: UA-Windowpixels
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAWindowpixels{ u8"UA-Windowpixels" };

					/// <summary>
					/// Header Name: Upgrade
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 6.7]
					/// </summary>
					const std::string Upgrade{ u8"Upgrade" };

					/// <summary>
					/// Header Name: URI
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string URI{ u8"URI" };

					/// <summary>
					/// Header Name: User-Agent
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.5.3]
					/// </summary>
					const std::string UserAgent{ u8"User-Agent" };

					/// <summary>
					/// Header Name: Variant-Vary
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string VariantVary{ u8"Variant-Vary" };

					/// <summary>
					/// Header Name: Vary
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.4]
					/// </summary>
					const std::string Vary{ u8"Vary" };

					/// <summary>
					/// Header Name: Version
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Version{ u8"Version" };

					/// <summary>
					/// Header Name: Via
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 5.7.1]
					/// </summary>
					const std::string Via{ u8"Via" };

					/// <summary>
					/// Header Name: Want-Digest
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string WantDigest{ u8"Want-Digest" };

					/// <summary>
					/// Header Name: Warning
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.5]
					/// </summary>
					const std::string Warning{ u8"Warning" };

					/// <summary>
					/// Header Name: WWW-Authenticate
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.1]
					/// </summary>
					const std::string WWWAuthenticate{ u8"WWW-Authenticate" };

					/// <summary>
					/// Header Name: X-Device-Accept
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAccept{ u8"X-Device-Accept" };

					/// <summary>
					/// Header Name: X-Device-Accept-Charset
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAcceptCharset{ u8"X-Device-Accept-Charset" };

					/// <summary>
					/// Header Name: X-Device-Accept-Encoding
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAcceptEncoding{ u8"X-Device-Accept-Encoding" };

					/// <summary>
					/// Header Name: X-Device-Accept-Language
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAcceptLanguage{ u8"X-Device-Accept-Language" };

					/// <summary>
					/// Header Name: X-Device-User-Agent
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceUserAgent{ u8"X-Device-User-Agent" };

					/// <summary>
					/// Header Name: X-Frame-Options
					/// Protocol: HTTP
					/// Status: Informational
					/// Defined In: [RFC7034]
					/// </summary>
					const std::string XFrameOptions{ u8"X-Frame-Options" };
					// Common but non-standard request headers

					/// <summary>
					/// Header Name: X-Requested-With
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XRequestedWith{ u8"X-Requested-With" };

					/// <summary>
					/// Header Name: DNT
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string DNT{ u8"DNT" };

					/// <summary>
					/// Header Name: X-Forwarded-For
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XForwardedFor{ u8"X-Forwarded-For" };

					/// <summary>
					/// Header Name: X-Forwarded-Host
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XForwardedHost{ u8"X-Forwarded-Host" };

					/// <summary>
					/// Header Name: X-Forwarded-Proto
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XForwardedProto{ u8"X-Forwarded-Proto" };

					/// <summary>
					/// Header Name: Front-End-Https
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string FrontEndHttps{ u8"Front-End-Https" };

					/// <summary>
					/// Header Name: X-Http-Method-Override
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XHttpMethodOverride{ u8"X-Http-Method-Override" };

					/// <summary>
					/// Header Name: X-ATT-DeviceId
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XATTDeviceId{ u8"X-ATT-DeviceId" };

					/// <summary>
					/// Header Name: X-Wap-Profile
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XWapProfile{ u8"X-Wap-Profile" };

					/// <summary>
					/// Header Name: Proxy-Connection
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string ProxyConnection{ u8"Proxy-Connection" };

					/// <summary>
					/// Header Name: X-UIDH
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XUIDH{ u8"X-UIDH" };

					/// <summary>
					/// Header Name: X-Csrf-Token
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XCsrfToken{ u8"X-Csrf-Token" };
					// Common but non-standard response headers

					/// <summary>
					/// Header Name: X-XSS-Protection
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XXSSProtection{ u8"X-XSS-Protection" };

					/// <summary>
					/// Header Name: Content-Security-Policy
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string ContentSecurityPolicy{ u8"Content-Security-Policy" };

					/// <summary>
					/// Header Name: X-Content-Security-Policy
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XContentSecurityPolicy{ u8"X-Content-Security-Policy" };

					/// <summary>
					/// Header Name: X-WebKit-CSP
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XWebKitCSP{ u8"X-WebKit-CSP" };

					/// <summary>
					/// Header Name: X-Content-Type-Options
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XContentTypeOptions{ u8"X-Content-Type-Options" };

					/// <summary>
					/// Header Name: X-Powered-By
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XPoweredBy{ u8"X-Powered-By" };

					/// <summary>
					/// Header Name: X-UA-Compatible
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XUACompatible{ u8"X-UA-Compatible" };

					/// <summary>
					/// Header Name: X-Content-Duration
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XContentDuration{ u8"X-Content-Duration" };

					/// <summary>
					/// Header Name: Get-Dictionary
					/// Protocol: HTTP
					/// Status: Non-Standard
					/// Defined In: Made up by Google to support SDHC compression.
					/// </summary>
					const std::string GetDictionary{ u8"Get-Dictionary" };

					/// <summary>
					/// Header Name: X-SDHC
					/// Protocol: HTTP
					/// Status: Non-Standard
					/// Defined In: Made up by Google to support SDHC compression.
					/// </summary>
					const std::string XSDHC{ u8"X-SDHC" };

					/// <summary>
					/// Header Name: Avail-Dictionary
					/// Protocol: HTTP
					/// Status: Non-Standard
					/// Defined In: Made up by Google to support SDHC compression.
					/// </summary>
					const std::string AvailDictionary{ u8"Avail-Dictionary" };

					/// <summary>
					/// Header Name: Alternate-Protocol
					/// Protocol: HTTP
					/// Status: Non-Standard
					/// Defined In: Made up by Google to hint to use QUIC over HTTP.
					/// </summary>
					const std::string AlternateProtocol{ u8"Alternate-Protocol" };

					/// <summary>
					/// Header Name: Alternate-Protocol
					/// Protocol: HTTP Extension
					/// Status: Unknown
					/// Defined In: http://httpwg.org/http-extensions/alt-svc.html
					/// </summary>
					const std::string AltSvc{ u8"Alt-Svc" };

				} /* namespace headers */
			} /* namespace http */
		} /* namespace util */
	} /* namespace httpengine */
} /* namespace te */