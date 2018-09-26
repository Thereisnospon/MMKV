/*
 * Tencent is pleased to support the open source community by making
 * MMKV available.
 *
 * Copyright (C) 2018 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Licensed under the BSD 3-Clause License (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *       https://opensource.org/licenses/BSD-3-Clause
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "MMKV.h"
#include "CodedInputData.h"
#include "CodedOutputData.h"
#include "InterProcessLock.h"
#include "MMBuffer.h"
#include "MMKVLog.h"
#include "MiniPBCoder.h"
#include "MmapedFile.h"
#include "PBUtility.h"
#include "ScopedLock.hpp"
#include "aes/AESCrypt.h"
#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

using namespace std;

static unordered_map<std::string, MMKV *> *g_instanceDic;
static ThreadLock g_instanceLock;
static std::string g_rootDir;

#define DEFAULT_MMAP_ID "mmkv.default"
constexpr uint32_t Fixed32Size = pbFixed32Size(0);

static string mappedKVPathWithID(const string &mmapID, MMKVMode mode);
static string crcPathWithID(const string &mmapID, MMKVMode mode);

enum : bool {
    KeepSequence = false,
    IncreaseSequence = true,
};

MMKV::MMKV(const std::string &mmapID, int size, MMKVMode mode, string *cryptKey)
    : m_mmapID(mmapID)
    , m_path(mappedKVPathWithID(m_mmapID, mode)) //根据mmapId创建数据存储文件路径
    , m_crcPath(crcPathWithID(m_mmapID, mode)) //meta 文件路径
    , m_metaFile(m_crcPath, DEFAULT_MMAP_SIZE, (mode & MMKV_ASHMEM) ? MMAP_ASHMEM : MMAP_FILE) //meta文件
    , m_crypter(nullptr)
    , m_fileLock(m_metaFile.getFd()) //用meta文件fd做文件锁
    , m_sharedProcessLock(&m_fileLock, SharedLockType) //用meta文件的文件锁封装一个共享锁
    , m_exclusiveProcessLock(&m_fileLock, ExclusiveLockType)//用meta文件的文件锁封装一个排它锁
    , m_isInterProcess((mode & MMKV_MULTI_PROCESS) != 0)
    , m_isAshmem((mode & MMKV_ASHMEM) != 0) {
    m_fd = -1;
    m_ptr = nullptr;
    m_size = 0;
    m_actualSize = 0;
    m_output = nullptr;
    //ashmen 模式
    if (m_isAshmem) {
        m_ashmemFile = new MmapedFile(m_mmapID, static_cast<size_t>(size), MMAP_ASHMEM);
        m_fd = m_ashmemFile->getFd();
    } else {
        m_ashmemFile = nullptr;
    }
    //密钥
    if (cryptKey && cryptKey->length() > 0) {
        m_crypter = new AESCrypt((const unsigned char *) cryptKey->data(), cryptKey->length());
    }

    m_needLoadFromFile = true;

    m_crcDigest = 0;

    m_sharedProcessLock.m_enable = m_isInterProcess;
    m_exclusiveProcessLock.m_enable = m_isInterProcess;

    // sensitive zone
    {
        //加共享锁
        SCOPEDLOCK(m_sharedProcessLock);
        //加载数据
        loadFromFile();
    }
}

MMKV::MMKV(const string &mmapID, int ashmemFD, int ashmemMetaFD, string *cryptKey)
    : m_mmapID(mmapID)
    , m_path("")
    , m_crcPath("")
    , m_metaFile(ashmemMetaFD)
    , m_crypter(nullptr)
    , m_fileLock(m_metaFile.getFd())
    , m_sharedProcessLock(&m_fileLock, SharedLockType)
    , m_exclusiveProcessLock(&m_fileLock, ExclusiveLockType)
    , m_isInterProcess(true)
    , m_isAshmem(true) {

    // check mmapID with ashmemID
    {
        auto ashmemID = m_metaFile.getName();
        size_t pos = ashmemID.find_last_of('.');
        if (pos != string::npos) {
            ashmemID.erase(pos, string::npos);
        }
        if (mmapID != ashmemID) {
            MMKVWarning("mmapID[%s] != ashmem[%s]", mmapID.c_str(), ashmemID.c_str());
        }
    }
    m_path = string(ASHMEM_NAME_DEF) + "/" + m_mmapID;
    m_crcPath = string(ASHMEM_NAME_DEF) + "/" + m_metaFile.getName();
    m_fd = ashmemFD;
    m_ptr = nullptr;
    m_size = 0;
    m_actualSize = 0;
    m_output = nullptr;

    if (m_isAshmem) {
        m_ashmemFile = new MmapedFile(m_fd);
    } else {
        m_ashmemFile = nullptr;
    }

    if (cryptKey && cryptKey->length() > 0) {
        m_crypter = new AESCrypt((const unsigned char *) cryptKey->data(), cryptKey->length());
    }

    m_needLoadFromFile = true;

    m_crcDigest = 0;

    m_sharedProcessLock.m_enable = m_isInterProcess;
    m_exclusiveProcessLock.m_enable = m_isInterProcess;

    // sensitive zone
    {
        SCOPEDLOCK(m_sharedProcessLock);
        loadFromFile();
    }
}

MMKV::~MMKV() {
    clearMemoryState();

    if (m_ashmemFile) {
        delete m_ashmemFile;
        m_ashmemFile = nullptr;
    }
    if (m_crypter) {
        delete m_crypter;
        m_crypter = nullptr;
    }
}

MMKV *MMKV::defaultMMKV(MMKVMode mode, string *cryptKey) {
    return mmkvWithID(DEFAULT_MMAP_ID, DEFAULT_MMAP_SIZE, mode, cryptKey);
}

void initialize() {
    g_instanceDic = new unordered_map<std::string, MMKV *>;
    g_instanceLock = ThreadLock();

    //testAESCrypt();

    MMKVInfo("page size:%d", DEFAULT_MMAP_SIZE);
}

void MMKV::initializeMMKV(const std::string &rootDir) {
    static pthread_once_t once_control = PTHREAD_ONCE_INIT;
    pthread_once(&once_control, initialize);

    g_rootDir = rootDir;
    char *path = strdup(g_rootDir.c_str());
    mkPath(path);
    free(path);

    MMKVInfo("root dir: %s", g_rootDir.c_str());
}

MMKV *MMKV::mmkvWithID(const std::string &mmapID, int size, MMKVMode mode, string *cryptKey) {

    if (mmapID.empty()) {
        return nullptr;
    }
    SCOPEDLOCK(g_instanceLock);

    auto itr = g_instanceDic->find(mmapID);
    if (itr != g_instanceDic->end()) {
        MMKV *kv = itr->second;
        return kv;
    }
    auto kv = new MMKV(mmapID, size, mode, cryptKey);
    (*g_instanceDic)[mmapID] = kv;
    return kv;
}

MMKV *MMKV::mmkvWithAshmemFD(const string &mmapID, int fd, int metaFD, string *cryptKey) {

    if (fd < 0) {
        return nullptr;
    }
    SCOPEDLOCK(g_instanceLock);

    auto itr = g_instanceDic->find(mmapID);
    if (itr != g_instanceDic->end()) {
        MMKV *kv = itr->second;
        kv->checkReSetCryptKey(fd, metaFD, cryptKey);
        return kv;
    }
    auto kv = new MMKV(mmapID, fd, metaFD, cryptKey);
    (*g_instanceDic)[mmapID] = kv;
    return kv;
}

void MMKV::onExit() {
    SCOPEDLOCK(g_instanceLock);

    for (auto &itr : *g_instanceDic) {
        MMKV *kv = itr.second;
        kv->sync();
        kv->clearMemoryState();
    }
}

const std::string &MMKV::mmapID() {
    return m_mmapID;
}

std::string MMKV::cryptKey() {
    SCOPEDLOCK(m_lock);

    if (m_crypter) {
        char key[AES_KEY_LEN];
        m_crypter->getKey(key);
        return string(key, strnlen(key, AES_KEY_LEN));
    }
    return "";
}

#pragma mark - really dirty work

void decryptBuffer(AESCrypt &crypter, MMBuffer &inputBuffer) {
    size_t length = inputBuffer.length();
    MMBuffer tmp(length);

    auto input = (unsigned char *) inputBuffer.getPtr();
    auto output = (unsigned char *) tmp.getPtr();
    crypter.decrypt(input, output, length);

    inputBuffer = std::move(tmp);
}

void MMKV::loadFromFile() {
    if (m_isAshmem) {
        loadFromAshmem();
        return;
    }
    //从mmap的内存地址读取meta数据
    m_metaInfo.read(m_metaFile.getMemory());
    //open mmkv 数据文件
    m_fd = open(m_path.c_str(), O_RDWR | O_CREAT, S_IRWXU);
    if (m_fd < 0) {
        MMKVError("fail to open:%s, %s", m_path.c_str(), strerror(errno));
    } else {
        m_size = 0;
        struct stat st = {0};
        //读取文件状态。(:文件大小
        if (fstat(m_fd, &st) != -1) {
            m_size = static_cast<size_t>(st.st_size);
        }
        // round up to (n * pagesize) 填充文件大小到页大小的整数倍
        if (m_size < DEFAULT_MMAP_SIZE || (m_size % DEFAULT_MMAP_SIZE != 0)) {
            size_t oldSize = m_size;
            m_size = ((m_size / DEFAULT_MMAP_SIZE) + 1) * DEFAULT_MMAP_SIZE;、
            //扩容
            if (ftruncate(m_fd, m_size) != 0) {
                MMKVError("fail to truncate [%s] to size %zu, %s", m_mmapID.c_str(), m_size,
                          strerror(errno));
                m_size = static_cast<size_t>(st.st_size);
            }
            //扩容的空间填充0
            zeroFillFile(m_fd, oldSize, m_size - oldSize);
        }
        //mmap mmkv数据文件到内存
        m_ptr = (char *) mmap(nullptr, m_size, PROT_READ | PROT_WRITE, MAP_SHARED, m_fd, 0);
        if (m_ptr == MAP_FAILED) {
            MMKVError("fail to mmap [%s], %s", m_mmapID.c_str(), strerror(errno));
        } else {
            //?? 从数据文件开头读取 实际存储的数据大小？？
            memcpy(&m_actualSize, m_ptr, Fixed32Size);
            MMKVInfo("loading [%s] with %zu size in total, file size is %zu", m_mmapID.c_str(),
                     m_actualSize, m_size);
            bool loaded = false;
            // 已经有数据了
            if (m_actualSize > 0) {
                if (m_actualSize < m_size && m_actualSize + Fixed32Size <= m_size) {
                    //crc 校验
                    if (checkFileCRCValid()) {
                        MMKVInfo("loading [%s] with crc %u sequence %u", m_mmapID.c_str(),
                                 m_metaInfo.m_crcDigest, m_metaInfo.m_sequence);
                        //越过文件开头的 数据大小区域，创建一个actualSize 大小的内存buffer
                        MMBuffer inputBuffer(m_ptr + Fixed32Size, m_actualSize, MMBufferNoCopy);
                        if (m_crypter) {
                            //解密
                            decryptBuffer(*m_crypter, inputBuffer);
                        }
                        //解析为 dic
                        m_dic = MiniPBCoder::decodeMap(inputBuffer);
                        // 写数据为 append 到原数据尾部
                        m_output = new CodedOutputData(m_ptr + Fixed32Size + m_actualSize,
                                                       m_size - Fixed32Size - m_actualSize);
                        loaded = true;
                    }
                }
            }
            if (!loaded) {
                //没加载成功，要写数据，加排它锁
                SCOPEDLOCK(m_exclusiveProcessLock);

                if (m_actualSize > 0) {
                    //重置大小为0
                    writeAcutalSize(0);
                }
                m_output = new CodedOutputData(m_ptr + Fixed32Size, m_size - Fixed32Size);
                //重新计算CRC
                recaculateCRCDigest();
            }
            MMKVInfo("loaded [%s] with %zu values", m_mmapID.c_str(), m_dic.size());
        }
    }

    if (!isFileValid()) {
        MMKVWarning("[%s] file not valid", m_mmapID.c_str());
    }

    m_needLoadFromFile = false;
}

void MMKV::loadFromAshmem() {
    m_metaInfo.read(m_metaFile.getMemory());

    if (m_fd < 0 || !m_ashmemFile) {
        MMKVError("ashmem file invalid %s, fd:%d", m_path.c_str(), m_fd);
    } else {
        m_size = m_ashmemFile->getFileSize();
        m_ptr = (char *) m_ashmemFile->getMemory();
        if (m_ptr != MAP_FAILED) {
            memcpy(&m_actualSize, m_ptr, Fixed32Size);
            MMKVInfo("loading [%s] with %zu size in total, file size is %zu", m_mmapID.c_str(),
                     m_actualSize, m_size);
            bool loaded = false;
            if (m_actualSize > 0) {
                if (m_actualSize < m_size && m_actualSize + Fixed32Size <= m_size) {
                    if (checkFileCRCValid()) {
                        MMKVInfo("loading [%s] with crc %u sequence %u", m_mmapID.c_str(),
                                 m_metaInfo.m_crcDigest, m_metaInfo.m_sequence);
                        MMBuffer inputBuffer(m_ptr + Fixed32Size, m_actualSize, MMBufferNoCopy);
                        if (m_crypter) {
                            decryptBuffer(*m_crypter, inputBuffer);
                        }
                        m_dic = MiniPBCoder::decodeMap(inputBuffer);
                        m_output = new CodedOutputData(m_ptr + Fixed32Size + m_actualSize,
                                                       m_size - Fixed32Size - m_actualSize);
                        loaded = true;
                    }
                }
            }
            if (!loaded) {
                SCOPEDLOCK(m_exclusiveProcessLock);

                if (m_actualSize > 0) {
                    writeAcutalSize(0);
                }
                m_output = new CodedOutputData(m_ptr + Fixed32Size, m_size - Fixed32Size);
                recaculateCRCDigest();
            }
            MMKVInfo("loaded [%s] with %zu values", m_mmapID.c_str(), m_dic.size());
        }
    }

    if (!isFileValid()) {
        MMKVWarning("[%s] ashmem not valid", m_mmapID.c_str());
    }

    m_needLoadFromFile = false;
}

// read from last m_position
void MMKV::partialLoadFromFile() {
    //重新读取 metainfo
    m_metaInfo.read(m_metaFile.getMemory());
    //暂存
    size_t oldActualSize = m_actualSize;
    //读取新的数据大小
    memcpy(&m_actualSize, m_ptr, Fixed32Size);
    MMKVDebug("loading [%s] with file size %zu, oldActualSize %zu, newActualSize %zu",
              m_mmapID.c_str(), m_size, oldActualSize, m_actualSize);

    if (m_actualSize > 0) {
        if (m_actualSize < m_size && m_actualSize + Fixed32Size <= m_size) {
            //比原来的数据大
            if (m_actualSize > oldActualSize) {
                size_t bufferSize = m_actualSize - oldActualSize;
                MMBuffer inputBuffer(m_ptr + Fixed32Size + oldActualSize, bufferSize,
                                     MMBufferNoCopy);
                // incremental update crc digest
                //计算 CRC 与读取的CRC 比较
                m_crcDigest = (uint32_t) crc32(m_crcDigest, (const uint8_t *) inputBuffer.getPtr(),
                                               static_cast<uInt>(inputBuffer.length()));
                //读取 这段时间 append 的数据。追加到当前 dict
                if (m_crcDigest == m_metaInfo.m_crcDigest) {
                    if (m_crypter) {
                        decryptBuffer(*m_crypter, inputBuffer);
                    }
                    auto dic = MiniPBCoder::decodeMap(inputBuffer, bufferSize);
                    for (auto &itr : dic) {
                        //m_dic[itr.first] = std::move(itr.second);
                        auto target = m_dic.find(itr.first);
                        if (target == m_dic.end()) {
                            m_dic.emplace(itr.first, std::move(itr.second));
                        } else {
                            target->second = std::move(itr.second);
                        }
                    }
                    //设置写指针
                    m_output->seek(bufferSize);

                    MMKVDebug("partial loaded [%s] with %zu values", m_mmapID.c_str(),
                              m_dic.size());
                    return;
                } else {
                    MMKVError("m_crcDigest[%u] != m_metaInfo.m_crcDigest[%u]", m_crcDigest,
                              m_metaInfo.m_crcDigest);
                }
            }
        }
    }
    // something is wrong, do a full load
    clearMemoryState();
    loadFromFile();
}

void MMKV::checkLoadData() {
    //被标记重新读取文件。直接重新读取文件
    if (m_needLoadFromFile) {
        SCOPEDLOCK(m_sharedProcessLock);

        m_needLoadFromFile = false;
        loadFromFile();
        return;
    }
    //TODO: WHY
    if (!m_isInterProcess) {
        return;
    }

    // TODO: atomic lock m_metaFile?
    MMKVMetaInfo metaInfo;
    //重新读取metainfo
    metaInfo.read(m_metaFile.getMemory());
    //序列号不一致，重新读取文件
    if (m_metaInfo.m_sequence != metaInfo.m_sequence) {
        MMKVInfo("[%s] oldSeq %u, newSeq %u", m_mmapID.c_str(), m_metaInfo.m_sequence,
                 metaInfo.m_sequence);
        SCOPEDLOCK(m_sharedProcessLock);

        clearMemoryState();
        loadFromFile();
    } else if (m_metaInfo.m_crcDigest != metaInfo.m_crcDigest) {
        MMKVDebug("[%s] oldCrc %u, newCrc %u", m_mmapID.c_str(), m_metaInfo.m_crcDigest,
                  metaInfo.m_crcDigest);
        SCOPEDLOCK(m_sharedProcessLock);

        size_t fileSize = 0;
        if (m_isAshmem) {
            fileSize = m_size;
        } else {
            struct stat st = {0};
            if (fstat(m_fd, &st) != -1) {
                fileSize = (size_t) st.st_size;
            }
        }
        //文件大小不一致，重新读取文件
        if (m_size != fileSize) {
            MMKVInfo("file size has changed [%s] from %zu to %zu", m_mmapID.c_str(), m_size,
                     fileSize);
            clearMemoryState();
            loadFromFile();
        } else {
            //文件大小一致
            partialLoadFromFile();
        }
    }
}

void MMKV::clearAll() {
    MMKVInfo("cleaning all key-values from [%s]", m_mmapID.c_str());
    SCOPEDLOCK(m_lock);
    SCOPEDLOCK(m_exclusiveProcessLock);

    if (m_needLoadFromFile && !m_isAshmem) {
        removeFile(m_path.c_str());
        loadFromFile();
        return;
    }

    if (m_ptr && m_ptr != MAP_FAILED) {
        // for truncate
        size_t size = std::min<size_t>(static_cast<size_t>(DEFAULT_MMAP_SIZE), m_size);
        memset(m_ptr, 0, size);
        if (msync(m_ptr, size, MS_SYNC) != 0) {
            MMKVError("fail to msync [%s]:%s", m_mmapID.c_str(), strerror(errno));
        }
    }
    if (!m_isAshmem) {
        if (m_fd >= 0) {
            if (m_size != DEFAULT_MMAP_SIZE) {
                MMKVInfo("truncating [%s] from %zu to %d", m_mmapID.c_str(), m_size,
                         DEFAULT_MMAP_SIZE);
                if (ftruncate(m_fd, DEFAULT_MMAP_SIZE) != 0) {
                    MMKVError("fail to truncate [%s] to size %d, %s", m_mmapID.c_str(),
                              DEFAULT_MMAP_SIZE, strerror(errno));
                }
            }
        }
    }

    clearMemoryState();
    loadFromFile();
}

void MMKV::clearMemoryState() {
    MMKVInfo("clearMemoryState [%s]", m_mmapID.c_str());
    SCOPEDLOCK(m_lock);
    if (m_needLoadFromFile) {
        return;
    }
    m_needLoadFromFile = true;

    m_dic.clear();

    if (m_crypter) {
        m_crypter->reset();
    }

    if (m_output) {
        delete m_output;
    }
    m_output = nullptr;

    if (!m_isAshmem) {
        if (m_ptr && m_ptr != MAP_FAILED) {
            if (munmap(m_ptr, m_size) != 0) {
                MMKVError("fail to munmap [%s], %s", m_mmapID.c_str(), strerror(errno));
            }
        }
        m_ptr = nullptr;

        if (m_fd >= 0) {
            if (close(m_fd) != 0) {
                MMKVError("fail to close [%s], %s", m_mmapID.c_str(), strerror(errno));
            }
        }
        m_fd = -1;
    }
    m_size = 0;
    m_actualSize = 0;
}

// since we use append mode, when -[setData: forKey:] many times, space may not be enough
// try a full rewrite to make space
bool MMKV::ensureMemorySize(size_t newSize) {
    if (!isFileValid()) {
        MMKVWarning("[%s] file not valid", m_mmapID.c_str());
        return false;
    }
    //需要的大小大于当前剩余的
    if (newSize >= m_output->spaceLeft()) {
        // try a full rewrite to make space
        static const int offset = pbFixed32Size(0);
        //当前数据 encode,( 因为dic保存的是无重复key的。而文件/内存中是有重复append的key的，所以重新encode，会重整空间
        MMBuffer data = MiniPBCoder::encodeDataWithObject(m_dic);
        //需要目标大小
        size_t lenNeeded = data.length() + offset + newSize;
        if (m_isAshmem) {
            //ashmen 不允许扩展
            if (lenNeeded > m_size) {
                MMKVWarning("ashmem %s reach size limit:%zu, consider configure with larger size",
                            m_mmapID.c_str(), m_size);
                return false;
            }
        } else {
            // 至少扩展 8 个单位的 newSize
            size_t futureUsage = newSize * std::max<size_t>(8, (m_dic.size() + 1) / 2);
            // 1. no space for a full rewrite, double it
            // 2. or space is not large enough for future usage, double it to avoid frequently full rewrite
            // 大于当前文件大小
            if (lenNeeded >= m_size || (lenNeeded + futureUsage) >= m_size) {
                size_t oldSize = m_size;
                do {
                    //一直double扩展。直到满足条件
                    m_size *= 2;
                } while (lenNeeded + futureUsage >= m_size);
                MMKVInfo(
                    "extending [%s] file size from %zu to %zu, incoming size:%zu, futrue usage:%zu",
                    m_mmapID.c_str(), oldSize, m_size, newSize, futureUsage);

                // if we can't extend size, rollback to old state
                //扩展文件大小
                if (ftruncate(m_fd, m_size) != 0) {
                    MMKVError("fail to truncate [%s] to size %zu, %s", m_mmapID.c_str(), m_size,
                              strerror(errno));
                    //回滚到原文件大小
                    m_size = oldSize;
                    return false;
                }
                //填充扩展的区域
                if (!zeroFillFile(m_fd, oldSize, m_size - oldSize)) {
                    MMKVError("fail to zeroFile [%s] to size %zu, %s", m_mmapID.c_str(), m_size,
                              strerror(errno));
                    //回滚到原文件大小
                    m_size = oldSize;
                    return false;
                }
                //解除原来的mmap映射
                if (munmap(m_ptr, oldSize) != 0) {
                    MMKVError("fail to munmap [%s], %s", m_mmapID.c_str(), strerror(errno));
                }
                //创建新的mmap映射
                m_ptr = (char *) mmap(m_ptr, m_size, PROT_READ | PROT_WRITE, MAP_SHARED, m_fd, 0);
                if (m_ptr == MAP_FAILED) {
                    MMKVError("fail to mmap [%s], %s", m_mmapID.c_str(), strerror(errno));
                }

                // check if we fail to make more space
                if (!isFileValid()) {
                    MMKVWarning("[%s] file not valid", m_mmapID.c_str());
                    return false;
                }
            }
        }
        //重新设置 crypter
        if (m_crypter) {
            m_crypter->reset();
            auto ptr = (unsigned char *) data.getPtr();
            m_crypter->encrypt(ptr, ptr, data.length());
        }
        //写回新的数据大小
        writeAcutalSize(data.length());

        delete m_output;
        m_output = new CodedOutputData(m_ptr + offset, m_size - offset);
        //写回数据。重新计算CRC
        m_output->writeRawData(data);
        recaculateCRCDigest();
    }
    return true;
}

void MMKV::writeAcutalSize(size_t actualSize) {
    assert(m_ptr != 0);
    assert(m_ptr != MAP_FAILED);

    memcpy(m_ptr, &actualSize, Fixed32Size);
    m_actualSize = actualSize;
}

const MMBuffer &MMKV::getDataForKey(const std::string &key) {
    SCOPEDLOCK(m_lock);
    checkLoadData();
    auto itr = m_dic.find(key);
    if (itr != m_dic.end()) {
        return itr->second;
    }
    static MMBuffer nan(0);
    return nan;
}

bool MMKV::setDataForKey(MMBuffer &&data, const std::string &key) {
    if (data.length() == 0 || key.empty()) {
        return false;
    }
    //线程锁？
    SCOPEDLOCK(m_lock);
    //写数据，加排他锁
    SCOPEDLOCK(m_exclusiveProcessLock);
    //写之前先看下是否要重新读取
    checkLoadData();

    // m_dic[key] = std::move(data);
    // 先 内存中 dic 中更新
    auto itr = m_dic.find(key);
    if (itr == m_dic.end()) {
        itr = m_dic.emplace(key, std::move(data)).first;
    } else {
        itr->second = std::move(data);
    }
    //追加到尾部
    return appendDataWithKey(itr->second, key);
}

bool MMKV::removeDataForKey(const std::string &key) {
    if (key.empty()) {
        return false;
    }
    //dict 中删除
    auto deleteCount = m_dic.erase(key);
    if (deleteCount > 0) {
        static MMBuffer nan(0);
        //追加一个空的key
        return appendDataWithKey(nan, key);
    }

    return false;
}

bool MMKV::appendDataWithKey(const MMBuffer &data, const std::string &key) {
    size_t keyLength = key.length();
    // size needed to encode the key
    size_t size = keyLength + pbRawVarint32Size((int32_t) keyLength);
    // size needed to encode the value
    size += data.length() + pbRawVarint32Size((int32_t) data.length());

    //排它锁
    SCOPEDLOCK(m_exclusiveProcessLock);

    bool hasEnoughSize = ensureMemorySize(size);

    if (!hasEnoughSize || !isFileValid()) {
        return false;
    }
    if (m_actualSize == 0) {
        auto allData = MiniPBCoder::encodeDataWithObject(m_dic);
        if (allData.length() > 0) {
            if (m_crypter) {
                m_crypter->reset();
                auto ptr = (unsigned char *) allData.getPtr();
                m_crypter->encrypt(ptr, ptr, allData.length());
            }
            writeAcutalSize(allData.length());
            m_output->writeRawData(allData); // note: don't write size of data
            recaculateCRCDigest();
            return true;
        }
        return false;
    } else {
        writeAcutalSize(m_actualSize + size);
        m_output->writeString(key);
        m_output->writeData(data); // note: write size of data

        auto ptr = (uint8_t *) m_ptr + Fixed32Size + m_actualSize - size;
        if (m_crypter) {
            m_crypter->encrypt(ptr, ptr, size);
        }
        //重新计算，不修改 sequence
        updateCRCDigest(ptr, size, KeepSequence);

        return true;
    }
}
//完全写回
bool MMKV::fullWriteback() {
    if (m_needLoadFromFile) {
        return true;
    }
    if (!isFileValid()) {
        MMKVWarning("[%s] file not valid", m_mmapID.c_str());
        return false;
    }

    if (m_dic.empty()) {
        clearAll();
        return true;
    }

    auto allData = MiniPBCoder::encodeDataWithObject(m_dic);
    SCOPEDLOCK(m_exclusiveProcessLock);
    if (allData.length() > 0 && isFileValid()) {
        if (allData.length() + Fixed32Size <= m_size) {
            if (m_crypter) {
                m_crypter->reset();
                auto ptr = (unsigned char *) allData.getPtr();
                m_crypter->encrypt(ptr, ptr, allData.length());
            }
            writeAcutalSize(allData.length());
            delete m_output;
            m_output = new CodedOutputData(m_ptr + Fixed32Size, m_size - Fixed32Size);
            m_output->writeRawData(allData); // note: don't write size of data
            recaculateCRCDigest();
            return true;
        } else {
            // ensureMemorySize will extend file & full rewrite, no need to write back again
            return ensureMemorySize(allData.length() + Fixed32Size - m_size);
        }
    }
    return false;
}

/**
 * 重设 加密的 key
 * @param cryptKey
 * @return
 */
bool MMKV::reKey(const std::string &cryptKey) {
    SCOPEDLOCK(m_lock);
    checkLoadData();

    if (m_crypter) {
        if (cryptKey.length() > 0) {
            string oldKey = this->cryptKey();
            if (cryptKey == oldKey) {
                return true;
            } else {
                // change encryption key
                MMKVInfo("reKey with new aes key");
                delete m_crypter;
                auto ptr = (const unsigned char *) cryptKey.data();
                m_crypter = new AESCrypt(ptr, cryptKey.length());
                return fullWriteback();
            }
        } else {
            // decryption to plain text
            MMKVInfo("reKey with no aes key");
            delete m_crypter;
            m_crypter = nullptr;
            return fullWriteback();
        }
    } else {
        if (cryptKey.length() > 0) {
            // transform plain text to encrypted text
            MMKVInfo("reKey with aes key");
            auto ptr = (const unsigned char *) cryptKey.data();
            m_crypter = new AESCrypt(ptr, cryptKey.length());
            return fullWriteback();
        } else {
            return true;
        }
    }
    return false;
}

void MMKV::checkReSetCryptKey(const std::string *cryptKey) {
    SCOPEDLOCK(m_lock);

    if (m_crypter) {
        if (cryptKey) {
            string oldKey = this->cryptKey();
            if (oldKey != *cryptKey) {
                MMKVInfo("setting new aes key");
                delete m_crypter;
                auto ptr = (const unsigned char *) cryptKey->data();
                m_crypter = new AESCrypt(ptr, cryptKey->length());

                checkLoadData();
            } else {
                // nothing to do
            }
        } else {
            MMKVInfo("reset aes key");
            delete m_crypter;
            m_crypter = nullptr;

            checkLoadData();
        }
    } else {
        if (cryptKey) {
            MMKVInfo("setting new aes key");
            auto ptr = (const unsigned char *) cryptKey->data();
            m_crypter = new AESCrypt(ptr, cryptKey->length());

            checkLoadData();
        } else {
            // nothing to do
        }
    }
}

void MMKV::checkReSetCryptKey(int fd, int metaFD, std::string *cryptKey) {
    SCOPEDLOCK(m_lock);

    checkReSetCryptKey(cryptKey);

    if (m_isAshmem) {
        if (m_fd != fd) {
            close(fd);
        }
        if (m_metaFile.getFd() != metaFD) {
            close(metaFD);
        }
    }
}

bool MMKV::isFileValid() {
    if (m_fd >= 0 && m_size > 0 && m_output && m_ptr && m_ptr != MAP_FAILED) {
        return true;
    }
    return false;
}

#pragma mark - crc

// assuming m_ptr & m_size is set
bool MMKV::checkFileCRCValid() {
    if (m_ptr && m_ptr != MAP_FAILED) {
        constexpr int offset = pbFixed32Size(0);
        //计算当前的CRC
        m_crcDigest =
            (uint32_t) crc32(0, (const uint8_t *) m_ptr + offset, (uint32_t) m_actualSize);
        //重新读取
        m_metaInfo.read(m_metaFile.getMemory());
        if (m_crcDigest == m_metaInfo.m_crcDigest) {
            return true;
        }
        MMKVError("check crc [%s] fail, crc32:%u, m_crcDigest:%u", m_mmapID.c_str(),
                  m_metaInfo.m_crcDigest, m_crcDigest);
    }
    return false;
}

void MMKV::recaculateCRCDigest() {
    if (m_ptr && m_ptr != MAP_FAILED) {
        m_crcDigest = 0;
        constexpr int offset = pbFixed32Size(0);
        //重新计算CRC，修改 sequence
        updateCRCDigest((const uint8_t *) m_ptr + offset, m_actualSize, IncreaseSequence);
    }
}

void MMKV::updateCRCDigest(const uint8_t *ptr, size_t length, bool increaseSequence) {
    if (!ptr) {
        return;
    }
    m_crcDigest = (uint32_t) crc32(m_crcDigest, ptr, (uint32_t) length);

    void *crcPtr = m_metaFile.getMemory();
    if (crcPtr == nullptr || crcPtr == MAP_FAILED) {
        return;
    }

    m_metaInfo.m_crcDigest = m_crcDigest;
    if (increaseSequence) {
        m_metaInfo.m_sequence++;
    }
    if (m_metaInfo.m_version == 0) {
        m_metaInfo.m_version = 1;
    }
    m_metaInfo.write(crcPtr);
}

#pragma mark - set & get

bool MMKV::setStringForKey(const std::string &value, const std::string &key) {
    if (key.empty()) {
        return false;
    }
    auto data = MiniPBCoder::encodeDataWithObject(value);
    return setDataForKey(std::move(data), key);
}

bool MMKV::setBytesForKey(const MMBuffer &value, const std::string &key) {
    if (key.empty()) {
        return false;
    }
    auto data = MiniPBCoder::encodeDataWithObject(value);
    return setDataForKey(std::move(data), key);
}

bool MMKV::setBool(bool value, const std::string &key) {
    if (key.empty()) {
        return false;
    }
    size_t size = pbBoolSize(value);
    //malloc一块内存
    MMBuffer data(size);
    //写到内存
    CodedOutputData output(data.getPtr(), size);
    output.writeBool(value);

    return setDataForKey(std::move(data), key);
}

bool MMKV::setInt32(int32_t value, const std::string &key) {
    if (key.empty()) {
        return false;
    }
    size_t size = pbInt32Size(value);
    MMBuffer data(size);
    CodedOutputData output(data.getPtr(), size);
    output.writeInt32(value);

    return setDataForKey(std::move(data), key);
}

bool MMKV::setInt64(int64_t value, const std::string &key) {
    if (key.empty()) {
        return false;
    }
    size_t size = pbInt64Size(value);
    MMBuffer data(size);
    CodedOutputData output(data.getPtr(), size);
    output.writeInt64(value);

    return setDataForKey(std::move(data), key);
}

bool MMKV::setFloat(float value, const std::string &key) {
    if (key.empty()) {
        return false;
    }
    size_t size = pbFloatSize(value);
    MMBuffer data(size);
    CodedOutputData output(data.getPtr(), size);
    output.writeFloat(value);

    return setDataForKey(std::move(data), key);
}

bool MMKV::setDouble(double value, const std::string &key) {
    if (key.empty()) {
        return false;
    }
    size_t size = pbDoubleSize(value);
    MMBuffer data(size);
    CodedOutputData output(data.getPtr(), size);
    output.writeDouble(value);

    return setDataForKey(std::move(data), key);
}

bool MMKV::setVectorForKey(const std::vector<std::string> &v, const std::string &key) {
    if (key.empty()) {
        return false;
    }
    auto data = MiniPBCoder::encodeDataWithObject(v);
    return setDataForKey(std::move(data), key);
}

bool MMKV::getStringForKey(const std::string &key, std::string &result) {
    if (key.empty()) {
        return false;
    }
    auto &data = getDataForKey(key);
    if (data.length() > 0) {
        result = MiniPBCoder::decodeString(data);
        return true;
    }
    return false;
}

MMBuffer MMKV::getBytesForKey(const std::string &key) {
    if (key.empty()) {
        return MMBuffer(0);
    }
    auto &data = getDataForKey(key);
    if (data.length() > 0) {
        return MiniPBCoder::decodeBytes(data);
    }
    return MMBuffer(0);
}

bool MMKV::getBoolForKey(const std::string &key, bool defaultValue) {
    if (key.empty()) {
        return defaultValue;
    }
    auto &data = getDataForKey(key);
    if (data.length() > 0) {
        CodedInputData input(data.getPtr(), data.length());
        return input.readBool();
    }
    return defaultValue;
}

int32_t MMKV::getInt32ForKey(const std::string &key, int32_t defaultValue) {
    if (key.empty()) {
        return defaultValue;
    }
    auto &data = getDataForKey(key);
    if (data.length() > 0) {
        CodedInputData input(data.getPtr(), data.length());
        return input.readInt32();
    }
    return defaultValue;
}

int64_t MMKV::getInt64ForKey(const std::string &key, int64_t defaultValue) {
    if (key.empty()) {
        return defaultValue;
    }
    auto &data = getDataForKey(key);
    if (data.length() > 0) {
        CodedInputData input(data.getPtr(), data.length());
        return input.readInt64();
    }
    return defaultValue;
}

float MMKV::getFloatForKey(const std::string &key, float defaultValue) {
    if (key.empty()) {
        return defaultValue;
    }
    auto &data = getDataForKey(key);
    if (data.length() > 0) {
        CodedInputData input(data.getPtr(), data.length());
        return input.readFloat();
    }
    return defaultValue;
}

double MMKV::getDoubleForKey(const std::string &key, double defaultValue) {
    if (key.empty()) {
        return defaultValue;
    }
    auto &data = getDataForKey(key);
    if (data.length() > 0) {
        CodedInputData input(data.getPtr(), data.length());
        return input.readDouble();
    }
    return defaultValue;
}

bool MMKV::getVectorForKey(const std::string &key, std::vector<std::string> &result) {
    if (key.empty()) {
        return false;
    }
    auto &data = getDataForKey(key);
    if (data.length() > 0) {
        result = MiniPBCoder::decodeSet(data);
        return true;
    }
    return false;
}

#pragma mark - enumerate

bool MMKV::containsKey(const std::string &key) {
    SCOPEDLOCK(m_lock);
    checkLoadData();
    return m_dic.find(key) != m_dic.end();
}

size_t MMKV::count() {
    SCOPEDLOCK(m_lock);
    checkLoadData();
    return m_dic.size();
}

size_t MMKV::totalSize() {
    SCOPEDLOCK(m_lock);
    checkLoadData();
    return m_size;
}

std::vector<std::string> MMKV::allKeys() {
    SCOPEDLOCK(m_lock);
    checkLoadData();

    vector<string> keys;
    for (const auto &itr : m_dic) {
        keys.push_back(itr.first);
    };
    return keys;
}

//删除key
void MMKV::removeValueForKey(const std::string &key) {
    if (key.empty()) {
        return;
    }
    SCOPEDLOCK(m_lock);
    SCOPEDLOCK(m_exclusiveProcessLock);
    checkLoadData();

    removeDataForKey(key);
}

void MMKV::removeValuesForKeys(const std::vector<std::string> &arrKeys) {
    if (arrKeys.empty()) {
        return;
    }
    if (arrKeys.size() == 1) {
        return removeValueForKey(arrKeys[0]);
    }

    SCOPEDLOCK(m_lock);
    SCOPEDLOCK(m_exclusiveProcessLock);
    checkLoadData();
    for (const auto &key : arrKeys) {
        m_dic.erase(key);
    }

    fullWriteback();
}

#pragma mark - file

void MMKV::sync() {
    SCOPEDLOCK(m_lock);
    if (m_needLoadFromFile || !isFileValid()) {
        return;
    }
    SCOPEDLOCK(m_exclusiveProcessLock);
    //磁盘与共享区同步
    if (msync(m_ptr, m_size, MS_SYNC) != 0) {
        MMKVError("fail to msync [%s]:%s", m_mmapID.c_str(), strerror(errno));
    }
}

bool MMKV::isFileValid(const std::string &mmapID) {
    string kvPath = mappedKVPathWithID(mmapID, MMKV_SINGLE_PROCESS);
    if (!isFileExist(kvPath)) {
        return true;
    }

    string crcPath = crcPathWithID(mmapID, MMKV_SINGLE_PROCESS);
    if (!isFileExist(crcPath.c_str())) {
        return false;
    }

    uint32_t crcFile = 0;
    MMBuffer *data = readWholeFile(crcPath.c_str());
    if (data) {
        MMKVMetaInfo metaInfo;
        metaInfo.read(data->getPtr());
        crcFile = metaInfo.m_crcDigest;
        delete data;
    } else {
        return false;
    }

    const int offset = pbFixed32Size(0);
    size_t actualSize = 0;
    MMBuffer *fileData = readWholeFile(kvPath.c_str());
    if (fileData) {
        actualSize = CodedInputData(fileData->getPtr(), fileData->length()).readFixed32();
        if (actualSize > fileData->length() - offset) {
            delete fileData;
            return false;
        }

        uint32_t crcDigest = (uint32_t) crc32(0, (const uint8_t *) fileData->getPtr() + offset,
                                              (uint32_t) actualSize);

        delete fileData;
        return crcFile == crcDigest;
    } else {
        return false;
    }
}

static string mappedKVPathWithID(const string &mmapID, MMKVMode mode) {
    return (mode & MMKV_ASHMEM) == 0 ? g_rootDir + "/" + mmapID
                                     : string(ASHMEM_NAME_DEF) + "/" + mmapID;
}

static string crcPathWithID(const string &mmapID, MMKVMode mode) {
    return (mode & MMKV_ASHMEM) == 0 ? g_rootDir + "/" + mmapID + ".crc" : mmapID + ".crc";
}
