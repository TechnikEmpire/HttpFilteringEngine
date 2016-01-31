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

#include <string>
#include <unordered_map>
#include <openssl/obj_mac.h>
#include <boost/predef.h>
#include "../../network/SocketTypes.hpp"
#include <mutex>
#include <thread>

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace secure
			{

				/// <summary>
				/// The BaseInMemoryCertificateStore class serves as a mechanism by which proxy
				/// client handlers can retrieve spoofed versions of validated upstream certificates
				/// in order to serve HTTPS clients requesting TLS connections. The
				/// BaseInMemoryCertificateStore itself does not search upstream for certficates to
				/// validate and spoof, but rather holds the sole responsibility of generating a
				/// root CA certificate, establishing trust with the OS host by installing said
				/// certificate, then issuing certificates to clients on demand.
				/// 
				/// As noted elsewhere in the documentation for this class, care must be taken not
				/// to improperly use this class. Clients absolutely must correctly validate
				/// upstream certificates before requesting a spoofed version to deliver to clients.
				/// Failing to do so will result in lying to clients about their security,
				/// potentially issuing a valid spoofed certificate that clients will trust, when in
				/// fact the original certificate is not valid for some reason. Any connection where
				/// an upstream certificate fails the standard validation should be terminated
				/// immediately and no data handed downstream to the connected client.
				/// </summary>
				class BaseInMemoryCertificateStore
				{

				public:

					/// <summary>
					/// Holds the cipher list that is set on every generated context.
					/// </summary>
					static const std::string ContextCipherList;

					/// <summary>
					/// Default constructor, delegates to the parameterized constructure which
					/// takes country code, organization name and common name, with default values.
					/// Be advised that the constructor that this delegates to can throw.
					/// </summary>
					BaseInMemoryCertificateStore();

					/// <summary>
					/// Constructs a new BaseInMemoryCertificateStore and generates a self signed CA
					/// certificate, storing the generated EVP_PKEY and X509 structures in the
					/// m_thisCaKeyPair and m_thisCa members respectively. This constructor invokes
					/// members that can throw.
					/// </summary>
					/// <param name="countryCode">
					/// The country code for the self signed CA to be generated.
					/// </param>
					/// <param name="organizationName">
					/// The organization name for the self signed CA to be generated.
					/// </param>
					/// <param name="commonName">
					/// The common name for the self signed CA to be generated.
					/// </param>
					BaseInMemoryCertificateStore(
						const std::string& countryCode, 
						const std::string& organizationName, 
						const std::string& commonName
						);

					/// <summary>
					/// Destructor iterates over all generated boost::asio::ssl::context pointers
					/// stored in the m_hostContexts member and attempts to correctly free the X509
					/// structure, the temporary negotiation EC key, and the EVP_PKEY structure for
					/// each context, finally calling delete on the parent boost::asio::ssl::context structure.
					/// </summary>
					virtual ~BaseInMemoryCertificateStore();

					/// <summary>
					/// Attempts to either retrieve an existing context for the supplied hostname,
					/// or clone the supplied certificate insofar as is necessary to pass inspection
					/// once signed with our CA. This means that the subject and subject alt names
					/// are copied. Once the certificate is spoofed successfully, a
					/// boost::asio::ssl::context is allocated and the generated certificate,
					/// keypair, and temporary negotiation EC_KEY are assigned to the newly
					/// allocated boost::asio::ssl::context.
					/// 
					/// The boost::asio::ssl::context is then stored, using the host name and all
					/// extracted subject alt names as keys to point to the same generated
					/// boost::asio::ssl::context. This is so that the same context can be
					/// discovered for every single host that the certificate is meant to handle.
					/// 
					/// Every generated boost::asio::ssl::context is set to be a TLS1.2 server
					/// context.
					/// 
					/// As with basically every other method in this class, this can throw
					/// runtime_error in the event that even a single openSSL operation does not
					/// return a value indicating a successful operation. The ::what() member of the
					/// thrown exception will provide detailed information about what went wrong.
					/// These must be handled and the messages routed through any available
					/// callbacks, as the design of this library is to provide a C API for certain
					/// targets.
					/// </summary>
					/// <param name="hostname">
					/// The host that the supplied certificate structure was received from. This
					/// will be used, along with all discovered SAN's in the supplied X509
					/// structure, to index the final generated server SSL context for lookup by
					/// future users.
					/// </param>
					/// <param name="originalCertificate">
					/// A valid pointer to the received upstream certificate to spoof. Note that
					/// users should have used the upstream SSL context, which loads the
					/// cURL/Mozilla ca-bundle for validation, to validate certificates before
					/// spoofing them. This method, this entire object, does no validation of
					/// certificates supplied to it. As such, take care to use the proper mechanisms
					/// to validate certificates before spoofing them, lets your clients curse you
					/// for transparently feeding them bad certificates which will pass as good
					/// certificates once issued from here.
					/// </param>
					/// <returns>
					/// A pointer to the generated boost::asio::ssl::context object that been
					/// configured to utilize the successfully spoofed certificate, keypair and
					/// temporary negotiation EC key in a server context.
					/// </returns>
					boost::asio::ssl::context* GetServerContext(const std::string& hostname, X509* certificate);

					/// <summary>
					/// Attempts to install the current temporary root CA certificate for
					/// transparent filtering to the appropriate OS specific filesystem certificate
					/// store. This must be overridden in an os specific derrived class.
					/// </summary>
					/// <returns>
					/// True if the operation succeeded and the current temporary root CA
					/// certificate was installed to the appropriate OS filesystem certificate
					/// store. False otherwise.
					/// 
					/// This method is assumed to throw in all derrived types, so runtime_errors
					/// need to be expected and correctly handled.
					/// </returns>
					virtual bool EstablishOsTrust() = 0;

					/// <summary>
					/// Searches the OS filesystem certificate store for any installed root CA
					/// certificates generated by this program and deletes them. Although there
					/// isn't any harm in not doing this, not doing this would make an awful mess,
					/// potentially building up useless CA certificates in the client's OS. The
					/// private key is of course never stored with the certificates, but rather is
					/// kept in memory. This is just about cleaning up our garbage. This must be
					/// overridden in an os specific derrived class.
					/// 
					/// This method is assumed to throw in all derrived types, so runtime_errors
					/// need to be expected and correctly handled.
					/// </summary>
					virtual void RevokeOsTrust() = 0;

					/// <summary>
					/// Attempts to write the given X509 structure to the given file path. Note that
					/// if the supplied path points to an existing file, this method will overwrite
					/// it. Use with caution.
					/// </summary>
					/// <param name="cert">
					/// A valid ptr to the X509 structure to write to file storage.
					/// </param>
					/// <param name="outputFilePath">
					/// The path to the file to write the output to.
					/// </param>
					/// <returns>
					/// True if the contents of the supplied X509 structure were written to file
					/// storage, false otherwise.
					/// </returns>
					virtual bool WriteCertificateToFile(X509* cert, const std::string& outputFilePath);

				protected:

					/// <summary>
					/// Lock for spoofing.
					/// </summary>
					using ScopedLock = std::lock_guard<std::mutex>;

					/// <summary>
					/// For synchronizing local storage of generated keys, certificates and contexts.
					/// </summary>
					std::mutex m_spoofMutex;

					/// <summary>
					/// Stores either the provided or default country code information to use for
					/// the self signed CA certificate.
					/// </summary>
					std::string m_caCountryCode;

					/// <summary>
					/// Stores either the provided or default common name information to use for
					/// the self signed CA certificate.
					/// </summary>
					std::string m_caCommonName;

					/// <summary>
					/// Stores either the provided or default organization name information to use
					/// for the self signed CA certificate.
					/// </summary>
					std::string m_caOrgName;

					/// <summary>
					/// Stores the generated CA certificate used to issue all spoofed certificates.
					/// </summary>
					X509* m_thisCa = nullptr;

					/// <summary>
					/// Stores the key information for the generated CA certificate used to issue
					/// and sign all spoofed certificates.
					/// </summary>
					EVP_PKEY* m_thisCaKeyPair = nullptr;

					/// <summary>
					/// Stores generated contexts using the host name as the lookup key. Due to the
					/// existence of SAN's or Subject Alternative Names, it's possible to have
					/// multiple keys pointing to the same structure. This makes cleanup a little tricky.
					/// </summary>
					std::unordered_map<std::string, boost::asio::ssl::context*> m_hostContexts;								

					/// <summary>
					/// Generates an EC key with the given named curve. As with basically every
					/// other method in this class, this can throw runtime_error in the event that
					/// even a single openSSL operation does not return a value indicating a
					/// successful operation. The ::what() member of the thrown exception will
					/// provide detailed information about what went wrong. These must be handled
					/// and the messages routed through any available callbacks, as the design of
					/// this library is to provide a C API for certain targets.
					/// </summary>
					/// <param name="namedCurveId">
					/// The named curve with which to generate the EC key. Default is
					/// NID_X9_62_prime256v1. It is advised that for maximum browser compatibility,
					/// that this default be unchanged.
					/// </param>
					/// <returns>
					/// A pointer to the generated EVP_PKEY structure containing the generated EC_KEY.
					/// </returns>
					EVP_PKEY* GenerateEcKey(const int namedCurveId = NID_X9_62_prime256v1) const;

					/// <summary>
					/// Generates a certificate, then sets its own name information as the issuer
					/// name information. Also adds additional contraints standard to a CA
					/// certificate. Internally delegates initial certificate generation to
					/// ::IssueCertificate(...), then modifies the output with the aforementioned changes.
					/// 
					/// As with basically every other method in this class, this can throw
					/// runtime_error in the event that even a single openSSL operation does not
					/// return a value indicating a successful operation. The ::what() member of the
					/// thrown exception will provide detailed information about what went wrong.
					/// These must be handled and the messages routed through any available
					/// callbacks, as the design of this library is to provide a C API for certain targets.
					/// </summary>
					/// <param name="issuerKeypair">
					/// The a valid pointer to the EVP_PKEY structure containing the generated EC
					/// key belonging to the issuer. Used to both sign the generated certificate and
					/// set the public key information of the X509 structure.
					/// </param>
					/// <param name="countryCode">
					/// The country code to write to the generated X509 structure.
					/// </param>
					/// <param name="organizationName">
					/// The organization name to write to the generated X509 structure.
					/// </param>
					/// <param name="commonName">
					/// The common name to write to the generated X509 structure.
					/// </param>
					/// <returns>
					/// A pointer to the generated X509 structure.
					/// </returns>
					X509* GenerateSelfSignedCert(EVP_PKEY* issuerKeypair, 
						const std::string& countryCode, 
						const std::string& organizationName, 
						const std::string& commonName
						) const;

					/// <summary>
					/// Generates a certificate, signing with the supplied issuer keypair if an
					/// issue keypair is supplied, setting the public key of the issued certified
					/// from the supplied certificateKeypair parameter. If bool isCA parameter is
					/// set to false, then the issuer name of the generated certificate will be
					/// extracted from the m_thisCA member. As such obviously m_thisCA must exist
					/// before call where the bool isCA parameter is set to false. If the bool isCA
					/// parameter is set to true, then as the certificate is generated, the issuer
					/// name information will be set to the generated X509 structure's generated
					/// name information.
					/// 
					/// Calling this method and suppling bool isCA to true is not sufficient to
					/// generate a complete self signed CA. Additional stasndard CA contraints must
					/// be written to the structure for a complete CA to be created. As such, use
					/// the ::GenerateSelfSignedCert(...) member to generate a complete, proper CA.
					/// 
					/// As with basically every other method in this class, this can throw
					/// runtime_error in the event that even a single openSSL operation does not
					/// return a value indicating a successful operation. The ::what() member of the
					/// thrown exception will provide detailed information about what went wrong.
					/// These must be handled and the messages routed through any available
					/// callbacks, as the design of this library is to provide a C API for certain
					/// targets.
					/// </summary>
					/// <param name="certificateKeypair">
					/// A valid pointer to a generated EVP_PKEY structure that will be used to write
					/// the public key portion of the generated certificate. That is to say, the key
					/// generation portion of generating any certificate must occur before
					/// generating the certificate itself through this method.
					/// </param>
					/// <param name="issuerKeypair">
					/// An optional pointer to the generated EVP_PKEY structure that will be used to
					/// sign the generated certificate if supplied. In the event of generating a CA
					/// certificate, supply the same keypair for both the certificateKeypair and
					/// issuerKeypair parameters. If the argument is nullptr, the certificate will
					/// not be signed at all.
					/// </param>
					/// <param name="isCA">
					/// Bool to indicate whether the generated certificate is purposed to be a CA
					/// certificate or not. Note that supplying "true" to this parameter does not
					/// create a complete, proper CA. All this parameter will do when the parameter
					/// is set to true is copy the generated X509_NAME information from generated
					/// X509 structure into the issuer X509_NAME portion of the structure. If the
					/// parameter value is "false", then the issuer X509_NAME data will be copied
					/// from the m_thisCA member. Therefore, ensure before issuing any non CA
					/// certificates that m_thisCA is already generated and valid.
					/// </param>
					/// <param name="countryCode">
					/// The country code to write to the generated X509 structure.
					/// </param>
					/// <param name="organizationName">
					/// The organization name to write to the generated X509 structure.
					/// </param>
					/// <param name="commonName">
					/// The common name to write to the generated X509 structure.
					/// </param>
					/// <returns>
					/// A pointer to the generated X509 structure.
					/// </returns>
					X509* IssueCertificate(
						EVP_PKEY* certificateKeypair, 
						EVP_PKEY* issuerKeypair, 
						const bool isCA, 
						const std::string& countryCode, 
						const std::string& organizationName, 
						const std::string& commonName
						) const;

					/// <summary>
					/// Adds the named X509V3 extension to an existing X509 structure. Note that
					/// this probably the only method in this object that does not throw on a
					/// failure. Rather, it will indicate a failure in the return value. From there
					/// however, any members that access this method and get a return value
					/// indicating a failure are most likely going to throw.
					/// </summary>
					/// <param name="cert">
					/// A valid pointer to an existing X509 structure to add the named extension
					/// data to.
					/// </param>
					/// <param name="nid">
					/// The named extension id.
					/// </param>
					/// <param name="strValue">
					/// The string value to write for the named extension.
					/// </param>
					/// <returns>
					/// True if the operation was a success and the data was written to the supplied
					/// X509 structure, false otherwise.
					/// </returns>
					bool Addx509Extension(X509* cert, int nid, std::string strValue) const;

				};

			} /* namespace secure */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */