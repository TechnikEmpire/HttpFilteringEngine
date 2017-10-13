/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#include <cstdint>
#include <limits>
#include <vector>
#include <utility>
#include <iostream>

#include <array>
#include <atomic>

#include <boost/predef/os.h>
#include "EngineCallbackTypes.h"

namespace te
{
	namespace httpengine
	{
		namespace util
		{
			namespace cb
			{
                /// <summary>
                /// The CStreamCopyUtil uses some template hacks to give us a global function pointer
                /// that will write to a member/local vector of our choosing. Basically, we generate N
                /// unique types of this class. As such, we have N "instances" of these global/C style writer
                /// function pointers and vector container pointers. We can then claim these pointers as
                /// members of a proxy class. This gives us N unique channels through which to have global
                /// writer callback channels which are also functionally equivalent to class members.
                /// </summary>
                template<bool T, size_t TT>
                struct CStreamCopyUtil
                {
                    template<bool IS, size_t SZ>
                    friend struct CStreamCopyUtilContainer;

                private:

                    CStreamCopyUtil() = delete;                    
                    CStreamCopyUtil(const CStreamCopyUtil&) = delete;
                    CStreamCopyUtil(const CStreamCopyUtil&&) = delete;
                    ~CStreamCopyUtil() = delete;

                    /// <summary>
                    /// Unique ID of this stream identifier.
                    /// </summary>
                    static constexpr size_t Id = TT;

                    /// <summary>
                    /// A pointer to the container to write to. This must be set on each new instance.
                    /// </summary>
                    static std::vector<char>* container;

                    /// <summary>
                    /// The writer function. Whatever data is pushed to this static function will be
                    /// written to the vector who's pointer has been set with the static container
                    /// pointer. With the template args, we get a unique type per class and thus, so
                    /// long as our integers are sufficiently unique over time, we don't need to
                    /// worry about multiple writers.
                    /// </summary>
                    /// <param name="data">
                    /// The data to write.
                    /// </param>
                    /// <param name="dataLength">
                    /// The length of the data to write.
                    /// </param>
                    static void Write(const char* data, const uint32_t dataLength);
                };

                template<bool T, size_t TT>
                std::vector<char>* CStreamCopyUtil<T, TT>::container = nullptr;

                template<bool T, size_t TT>
                inline void CStreamCopyUtil<T, TT>::Write(const char* data, const uint32_t dataLength)
                {
                    if (container != nullptr && data != nullptr && dataLength > 0)
                    {
                        container->reserve(container->size() + dataLength);
                        std::copy(data, data + dataLength, std::back_inserter((*container)));
                    }
                }

                struct CStreamCopyUtilProxy
                {
                    template<bool TT, size_t ArrSize>
                    friend struct CStreamCopyUtilContainer;

                private:
                    const CustomResponseStreamWriter m_writeFunc = nullptr;

                    std::vector<char>** m_container = nullptr;

                public:
                    const CustomResponseStreamWriter Claim(std::vector<char>* myBin) const noexcept
                    {
                        if ((*m_container) != nullptr)
                        {
                            return nullptr;
                        }

                        (*m_container) = myBin;

                        return m_writeFunc;
                    }

                    const void Release() const noexcept
                    {
                        (*m_container) = nullptr;
                    }

                private:
                    constexpr CStreamCopyUtilProxy(const CustomResponseStreamWriter writeFunc, std::vector<char>** cont) noexcept : m_writeFunc(writeFunc)
                    {
                        m_container = cont;
                    }
                };

                template<bool TT, size_t ArrSize>
                struct CStreamCopyUtilContainer
                {
                private:

                    template <size_t sIdx, size_t... Idxb>
                    static constexpr std::array<CStreamCopyUtilProxy, 1000> MakeStreamInternalArrayImpl(std::index_sequence<Idxb...>) noexcept
                    {
                        return
                        {
                            CStreamCopyUtilProxy
                            {
                                CStreamCopyUtil<TT, !TT ? (Idxb)+(1000 * (sIdx)) : (Idxb)+(1000 * (sIdx)) + (1000 * (ArrSize))>::Write, 
                                &CStreamCopyUtil<TT, !TT ? (Idxb)+(1000 * (sIdx)) : (Idxb)+(1000 * (sIdx)) + (1000 * (ArrSize))>::container
                            }...
                        };
                    }

                    template <size_t... Idxa>
                    static constexpr std::array<std::array<CStreamCopyUtilProxy, 1000>, ArrSize> MakeStreamArrayImpl(std::index_sequence<Idxa...>) noexcept
                    {
                        return
                        {
                            MakeStreamInternalArrayImpl<Idxa>(std::make_index_sequence<1000>{})...
                        };
                    }

                    static constexpr std::array<std::array<CStreamCopyUtilProxy, 1000>, ArrSize> m_arr = MakeStreamArrayImpl(std::make_index_sequence<ArrSize>{});

                public:

                    static constexpr size_t size() noexcept
                    {
                        return ArrSize * 1000;
                    }

                    static struct TempWriterChannel ClaimNextChannel(std::vector<char>* outContainer) noexcept;

                private:

                    static std::atomic_uint32_t s_acquireIdx;
                };

                struct TempWriterChannel
                {
                    template<bool TT, size_t ArrSize>
                    friend struct CStreamCopyUtilContainer;

                private:

                    CustomResponseStreamWriter m_writer;

                    const CStreamCopyUtilProxy* m_parent;

                    bool m_isValid;

                    TempWriterChannel(const CStreamCopyUtilProxy& parent, std::vector<char>* outContainer) noexcept
                    {
                        m_parent = &parent;
                        m_writer = m_parent->Claim(outContainer);
                        m_isValid = m_writer != nullptr;
                    }

                    TempWriterChannel(TempWriterChannel&) = delete;

                public:

                    TempWriterChannel(TempWriterChannel&& other) noexcept
                    {
                        m_writer = other.m_writer;
                        m_parent = other.m_parent;
                        m_isValid = other.m_isValid;

                        other.m_isValid = false;
                    }

                    ~TempWriterChannel() noexcept
                    {
                        if (m_isValid && m_parent != nullptr)
                        {
                            m_parent->Release();
                        }
                    }

                    /// <summary>
                    /// Gets whether or not this channel was claimed. If this is false, it means that all available
                    /// channels have been exhausted, and you should not use the object any further.
                    /// </summary>
                    /// <returns></returns>
                    const bool IsValid() const noexcept
                    {
                        return m_writer != nullptr;
                    }

                    /// <summary>
                    /// Gets the raw writer function for external use.
                    /// </summary>
                    /// <returns>
                    /// The raw writer function for external use.
                    /// </returns>
                    const CustomResponseStreamWriter GetWriter() const noexcept
                    {
                        return m_writer;
                    }

                    /// <summary>
                    /// Writes N bytes from the supplied data pointer to the channel.
                    /// </summary>
                    /// <param name="data">
                    /// The data to write.
                    /// </param>
                    /// <param name="dataLen">
                    /// The number of bytes from the supplied data pointer to write.
                    /// </param>
                    const void Write(const char* data, const uint32_t dataLen) const noexcept
                    {
                        if (m_isValid)
                        {
                            m_writer(data, dataLen);
                        }
                    }
                };

                template<bool TT, size_t ArrSize>
                constexpr std::array<std::array<CStreamCopyUtilProxy, 1000>, ArrSize> CStreamCopyUtilContainer<TT, ArrSize>::m_arr;

                template<bool TT, size_t ArrSize>
                std::atomic_uint32_t CStreamCopyUtilContainer<TT, ArrSize>::s_acquireIdx = 0;

                template<bool TT, size_t ArrSize>
                inline TempWriterChannel CStreamCopyUtilContainer<TT, ArrSize>::ClaimNextChannel(std::vector<char>* outContainer) noexcept
                {
                    auto myIdx = s_acquireIdx++;

                    // Something to note here. We're using a uint32_t for our auto increment index. These indexes
                    // are supposed to keep us (ArrSize * 1000) channels apart between the oldest and newest claimed
                    // channels. However, the max value of our uint32_t is 4294967295 before it will roll over
                    // back to zero.
                    //
                    // Given the below formula, that means that, on the last index before the integer overflows
                    // back to zero, the last valid index will have been 7295. Observe:
                    // 
                    // Assuming ArrSize is 10, boundary = 10000
                    // std::floor(4294967295 / boundary) = 429496
                    // 4294967295 - ((boundary * 429496) = 4294960000) = 7295.
                    // Next index will be 0.
                    // As such, we can only guarantee that on an ArrSize of 10, the oldest and newest claimed
                    // channels are guaranteed to be at least 7294 indices apart.

                    myIdx = myIdx - static_cast<uint32_t>((ArrSize * 1000) * std::floor((myIdx / (ArrSize * 1000))));

                    return TempWriterChannel
                    {
                        m_arr[static_cast<size_t>(std::floor((myIdx / 1000)))][myIdx % 1000],
                        outContainer
                    };
                }
			}
		}
	}
}
