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

#include "WindowsInMemoryCertificateStore.hpp"

// This crazyness is required to include the necessary headers to work with the Windows OS
// certificate store. There are name conflicts between those headers and openSSL, of course.
#if BOOST_OS_WINDOWS
	#undef _WINSOCKAPI_
	#define _WINSOCKAPI_
	#define NOCRYPT
	#include <windows.h>
	#include <wincrypt.h>

	#ifdef OPENSSL_SYS_WIN32
		#undef X509_NAME
		#undef X509_EXTENSIONS
		#undef X509_CERT_PAIR
		#undef PKCS7_ISSUER_AND_SERIAL
		#undef OCSP_RESPONSE
	#endif // ifdef OPENSSL_SYS_WIN32
#endif // if BOOST_OS_WINDOWS

#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace secure
			{
				
				WindowsInMemoryCertificateStore::WindowsInMemoryCertificateStore() :
					BaseInMemoryCertificateStore()
				{
					
				}

				WindowsInMemoryCertificateStore::WindowsInMemoryCertificateStore(
					const std::string& countryCode,
					const std::string& organizationName,
					const std::string& commonName
					) : BaseInMemoryCertificateStore(						
						countryCode, 
						organizationName, 
						commonName
						)
				{
					
				}

				WindowsInMemoryCertificateStore::~WindowsInMemoryCertificateStore()
				{
					
				}

				bool WindowsInMemoryCertificateStore::EstablishOsTrust()
				{
					HCERTSTORE hSysStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");

					bool caAreadyGenerated = (m_thisCa != nullptr);

					if (hSysStore != nullptr && caAreadyGenerated)
					{
						unsigned char *buf = nullptr;

						int encodedBytesLen = i2d_X509(m_thisCa, &buf);

						CertAddEncodedCertificateToStore(hSysStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, buf, encodedBytesLen, CERT_STORE_ADD_REPLACE_EXISTING, NULL);

						CertCloseStore(hSysStore, 0);

						OPENSSL_free(buf);

						return true;
					}
					else
					{
						if (!caAreadyGenerated)
						{
							throw std::runtime_error("In WindowsInMemoryCertificateStore::EstablishOsTrust() - Attempted to install self signed certificate, to find that self signed cert is nullptr!");
						}
						else
						{
							throw std::runtime_error("In WindowsInMemoryCertificateStore::EstablishOsTrust() - Failed to open OS root certificate store.");
						}
						
					}

					return false;
				}

				void WindowsInMemoryCertificateStore::RevokeOsTrust()
				{
					HCERTSTORE hSysStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");

					if (hSysStore != nullptr)
					{
						char pszNameString[256];
						PCCERT_CONTEXT pCert = nullptr;

						bool shouldRemove = false;

						while ((pCert = CertEnumCertificatesInStore(hSysStore, pCert)) != nullptr)
						{
							shouldRemove = false;

							if (CertGetNameString(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, pszNameString, 128))
							{
								std::string certName(pszNameString);

								if (certName.compare(m_caCommonName) == 0)
								{
									shouldRemove = true;
								}
							}

							if (shouldRemove && pCert != nullptr)
							{
								if (!CertDeleteCertificateFromStore(pCert))
								{
									throw std::runtime_error("In WindowsInMemoryCertificateStore::RevokeOsTrust() - Error removing old CA from OS store.");
								}
								else 
								{
									// Has to happen in order to start pulling certs from the start of the store
									// after we've done a delete.
									pCert = nullptr;
								}								
							}
						}

						CertCloseStore(hSysStore, 0);
					}
					else
					{
						throw std::runtime_error("In WindowsInMemoryCertificateStore::RevokeOsTrust() - Failed to open OS root certificate store.");
					}
				}

			} /* namespace secure */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */